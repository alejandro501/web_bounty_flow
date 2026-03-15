package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rojo/hack/web_bounty_flow/pkg/app"
	"github.com/rojo/hack/web_bounty_flow/pkg/config"
	"github.com/rojo/hack/web_bounty_flow/pkg/configstore"
)

// Server provides the HTTP layer for interacting with the bounty flow.
type Server struct {
	cfg    *config.Config
	app    *app.App
	logger *log.Logger
	mux    *http.ServeMux

	mu            sync.Mutex
	running       bool
	status        string
	runCancel     context.CancelFunc
	abortMode     string
	paused        bool
	logMu         sync.Mutex
	logLines      []string
	logPath       string
	stepMu        sync.Mutex
	steps         []app.Step
	stepState     map[string]app.StepStatus
	stepsPath     string
	configStore   *configstore.Store
	xssMu         sync.Mutex
	xssRunning    bool
	xssStatus     string
	xssLastRun    string
	torEnabled    bool
	torProbe      app.EgressProbe
	torProbeAt    string
	proxyHost     string
	proxyPort     int
	proxyEnabled  bool
	leadStateMu   sync.Mutex
	leadStatePath string
	leadStates    map[string]leadState
}

// New creates a new HTTP server wired to the bounty flow.
func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		status: "idle",
	}
	s.logPath = filepath.Join(cfg.Paths.LogsDir, "flow.log")
	s.stepsPath = filepath.Join(cfg.Paths.LogsDir, "steps_state.json")
	s.leadStatePath = filepath.Join(filepath.Dir(cfg.Lists.Domains), "leads_state.json")
	s.proxyHost = "localhost"
	s.proxyPort = 8080
	s.leadStates = map[string]leadState{}
	s.initSteps()
	s.loadPersistedLogs()
	s.loadLeadStates()
	s.logger = log.New(io.MultiWriter(os.Stdout, s), "[bflow-server] ", log.LstdFlags)
	s.initConfigStore()
	appLogger := log.New(io.MultiWriter(os.Stdout, s), "[bflow] ", log.LstdFlags)
	s.app = app.New(cfg, appLogger, s, s.updateStep, s.configStore)
	s.applyNetworkSettingsToApp()

	s.mux.HandleFunc("/api/upload", s.corsMiddleware(s.uploadHandler))
	s.mux.HandleFunc("/api/url", s.corsMiddleware(s.urlHandler))
	s.mux.HandleFunc("/api/run", s.corsMiddleware(s.runHandler))
	s.mux.HandleFunc("/api/run/stop", s.corsMiddleware(s.stopHandler))
	s.mux.HandleFunc("/api/run/pause", s.corsMiddleware(s.pauseHandler))
	s.mux.HandleFunc("/api/run/clear", s.corsMiddleware(s.clearResultsHandler))
	s.mux.HandleFunc("/api/status", s.corsMiddleware(s.statusHandler))
	s.mux.HandleFunc("/api/logs", s.corsMiddleware(s.logsHandler))
	s.mux.HandleFunc("/api/config", s.corsMiddleware(s.configHandler))
	s.mux.HandleFunc("/api/config/flow-tools", s.corsMiddleware(s.flowToolsConfigHandler))
	s.mux.HandleFunc("/api/config/providers/", s.corsMiddleware(s.providerConfigHandler))
	s.mux.HandleFunc("/api/network", s.corsMiddleware(s.networkHandler))
	s.mux.HandleFunc("/api/dorking/github/run", s.corsMiddleware(s.githubRunHandler))
	s.mux.HandleFunc("/api/steps", s.corsMiddleware(s.stepsHandler))
	s.mux.HandleFunc("/api/list", s.corsMiddleware(s.listHandler))
	s.mux.HandleFunc("/api/notes", s.corsMiddleware(s.notesHandler))
	s.mux.HandleFunc("/api/tools", s.corsMiddleware(s.toolsHandler))
	s.mux.HandleFunc("/api/live-webservers", s.corsMiddleware(s.liveWebserversHandler))
	s.mux.HandleFunc("/api/amass-enum", s.corsMiddleware(s.amassEnumHandler))
	s.mux.HandleFunc("/api/progress/subdomain", s.corsMiddleware(s.subdomainProgressHandler))
	s.mux.HandleFunc("/api/leads", s.corsMiddleware(s.leadsHandler))
	s.mux.HandleFunc("/api/leads/state", s.corsMiddleware(s.leadStateHandler))
	s.mux.HandleFunc("/api/leads/replay", s.corsMiddleware(s.leadReplayHandler))
	s.mux.HandleFunc("/api/chaos", s.corsMiddleware(s.chaosHandler))
	s.mux.HandleFunc("/api/manual/xss/run", s.corsMiddleware(s.manualXSSRunHandler))
	s.mux.HandleFunc("/api/manual/xss/status", s.corsMiddleware(s.manualXSSStatusHandler))
	s.mux.HandleFunc("/", s.corsMiddleware(s.rootHandler))

	return s
}

type stepResponse struct {
	ID     string         `json:"id"`
	Label  string         `json:"label"`
	Status app.StepStatus `json:"status"`
}

type configResponse struct {
	Version   int                                       `json:"version"`
	Providers map[string]*configstore.DecryptedProvider `json:"providers"`
}

type keyPayload struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Active bool   `json:"active"`
}

type settingsPayload struct {
	AutoRun bool `json:"auto_run"`
}

type networkResponse struct {
	TorEnabled   bool   `json:"tor_enabled"`
	ProxyEnabled bool   `json:"proxy_enabled"`
	ProxyHost    string `json:"proxy_host,omitempty"`
	ProxyPort    int    `json:"proxy_port,omitempty"`
	ProbeMode    string `json:"probe_mode,omitempty"`
	ProbeIP      string `json:"probe_ip,omitempty"`
	ProbeAt      string `json:"probe_at,omitempty"`
	ProbeError   string `json:"probe_error,omitempty"`
	ProbeSrc     string `json:"probe_source,omitempty"`
}

type networkPayload struct {
	TorEnabled   bool   `json:"tor_enabled"`
	ProxyEnabled bool   `json:"proxy_enabled"`
	ProxyHost    string `json:"proxy_host"`
	ProxyPort    int    `json:"proxy_port"`
}

// ListenAndServe starts the configured HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	s.logger.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func (s *Server) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "bounty flow server is alive")
}

type uploadResponse struct {
	Status string `json:"status"`
}

type urlRequest struct {
	ListType string `json:"list_type"`
	URL      string `json:"url"`
}

type urlResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type statusResponse struct {
	Running bool   `json:"running"`
	Status  string `json:"status"`
}

type liveWebserverResponse struct {
	Present bool               `json:"present"`
	Count   int                `json:"count"`
	Rows    []liveWebserverRow `json:"rows"`
}

type amassEnumResponse struct {
	Present bool           `json:"present"`
	Count   int            `json:"count"`
	Rows    []amassEnumRow `json:"rows"`
}

type subdomainToolProgress struct {
	Name    string `json:"name"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Percent int    `json:"percent"`
}

type subdomainProgressResponse struct {
	TotalWildcards int                     `json:"total_wildcards"`
	OverallDone    int                     `json:"overall_done"`
	OverallPercent int                     `json:"overall_percent"`
	Tools          []subdomainToolProgress `json:"tools"`
}

type notePayload struct {
	Content string `json:"content"`
}

type listPayload struct {
	Content string `json:"content"`
}

type liveWebserverRow struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	WebServer     string   `json:"web_server"`
	Technologies  []string `json:"technologies"`
	ContentLength int      `json:"content_length"`
}

type amassEnumRow struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	ASN    int    `json:"asn"`
	Source string `json:"source"`
	Tag    string `json:"tag"`
}

type leadItem struct {
	ID           string         `json:"id"`
	Category     string         `json:"category"`
	Family       string         `json:"family,omitempty"`
	Severity     string         `json:"severity"`
	ROI          int            `json:"roi"`
	Wildcard     string         `json:"wildcard"`
	Domain       string         `json:"domain"`
	Target       string         `json:"target"`
	Reasons      []string       `json:"reasons,omitempty"`
	ManualAction string         `json:"manual_action,omitempty"`
	Evidence     map[string]any `json:"evidence,omitempty"`
	Source       string         `json:"source"`
	Timestamp    string         `json:"timestamp,omitempty"`
	Done         bool           `json:"done"`
	Bucket       string         `json:"bucket,omitempty"`
}

type leadsDomainGroup struct {
	Domain      string     `json:"domain"`
	Wildcard    string     `json:"wildcard"`
	ROI         int        `json:"roi"`
	LeadCount   int        `json:"lead_count"`
	HighCount   int        `json:"high_count"`
	MediumCount int        `json:"medium_count"`
	LowCount    int        `json:"low_count"`
	Leads       []leadItem `json:"leads"`
}

type leadsWildcardGroup struct {
	Wildcard    string             `json:"wildcard"`
	ROI         int                `json:"roi"`
	LeadCount   int                `json:"lead_count"`
	DomainCount int                `json:"domain_count"`
	Domains     []leadsDomainGroup `json:"domains"`
}

type leadsResponse struct {
	Present                bool                 `json:"present"`
	UpdatedAt              string               `json:"updated_at"`
	TotalLeads             int                  `json:"total_leads"`
	TotalROI               int                  `json:"total_roi"`
	Wildcards              []leadsWildcardGroup `json:"wildcards"`
	HitsWildcards          []leadsWildcardGroup `json:"hits_wildcards"`
	InvestigationWildcards []leadsWildcardGroup `json:"investigation_wildcards"`
	ArchiveWildcards       []leadsWildcardGroup `json:"archive_wildcards"`
	HitsCount              int                  `json:"hits_count"`
	InvestigationCount     int                  `json:"investigation_count"`
	ArchiveCount           int                  `json:"archive_count"`
}

type leadState struct {
	Done      bool   `json:"done"`
	Bucket    string `json:"bucket,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type toolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Required  bool   `json:"required"`
	Notes     string `json:"notes,omitempty"`
}

type manualXSSRunRequest struct {
	Target     string `json:"target"`
	AuthHeader string `json:"auth_header"`
}

type manualXSSStatusResponse struct {
	Running bool   `json:"running"`
	Status  string `json:"status"`
	LastRun string `json:"last_run"`
}

func (s *Server) liveWebserversHandler(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "live-webservers.jsonl")
	resp := liveWebserverResponse{Present: false, Rows: nil, Count: 0}

	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		resp.Present = true
		rows, readErr := readLiveWebserversJSONL(path)
		if readErr == nil {
			resp.Rows = rows
			resp.Count = len(rows)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) amassEnumHandler(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "amass", "amass_enum.jsonl")
	resp := amassEnumResponse{Present: false, Rows: nil, Count: 0}

	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		resp.Present = true
		rows, readErr := readAmassEnumJSONL(path)
		if readErr == nil {
			resp.Rows = rows
			resp.Count = len(rows)
		}
	}
	if resp.Count == 0 {
		fallbackRows, fallbackErr := readAmassEnumFromSeedText(filepath.Dir(path))
		if fallbackErr == nil && len(fallbackRows) > 0 {
			resp.Present = true
			resp.Rows = fallbackRows
			resp.Count = len(fallbackRows)
		}
	}
	if len(resp.Rows) > 0 {
		resp.Rows = normalizeAmassRows(resp.Rows)
		resp.Count = len(resp.Rows)
		resp.Present = resp.Count > 0
		s.syncIPsFromAmassRows(resp.Rows)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) subdomainProgressHandler(w http.ResponseWriter, r *http.Request) {
	wildcards := readListLines(s.cfg.Lists.Wildcards)
	total := len(uniqueNormalizedSeeds(wildcards))
	rawRoot := filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "raw")

	toolCounts := []struct {
		name string
		dir  string
		ext  string
	}{
		{name: "amass", dir: filepath.Join(rawRoot, "amass"), ext: ".txt"},
		{name: "sublist3r", dir: filepath.Join(rawRoot, "sublist3r"), ext: ".txt"},
		{name: "assetfinder", dir: filepath.Join(rawRoot, "assetfinder"), ext: ".txt"},
		{name: "gau", dir: filepath.Join(rawRoot, "gau"), ext: ".txt"},
		{name: "ctl", dir: filepath.Join(rawRoot, "ctl"), ext: ".json"},
		{name: "subfinder", dir: filepath.Join(rawRoot, "subfinder"), ext: ".txt"},
		{name: "chaos", dir: filepath.Join(rawRoot, "chaos"), ext: ".json"},
	}
	enabledTools := s.loadSubdomainToolSettings()
	filtered := toolCounts[:0]
	for _, tool := range toolCounts {
		if enabledTools[tool.name] {
			filtered = append(filtered, tool)
		}
	}
	toolCounts = filtered

	resp := subdomainProgressResponse{TotalWildcards: total}
	if total <= 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	sumDone := 0
	for _, tool := range toolCounts {
		done := countFilesByExt(tool.dir, tool.ext)
		if done > total {
			done = total
		}
		percent := int(float64(done) * 100.0 / float64(total))
		sumDone += done
		resp.Tools = append(resp.Tools, subdomainToolProgress{
			Name:    tool.name,
			Done:    done,
			Total:   total,
			Percent: percent,
		})
	}

	if len(toolCounts) > 0 {
		avgDone := int(math.Round(float64(sumDone) / float64(len(toolCounts))))
		if avgDone < 0 {
			avgDone = 0
		}
		if avgDone > total {
			avgDone = total
		}
		resp.OverallDone = avgDone
		resp.OverallPercent = int(float64(avgDone) * 100.0 / float64(total))
	}

	subdomainStepIDs := []string{
		app.StepSubdomainEnum,
		app.StepAmass,
		app.StepSublist3r,
		app.StepAssetfinder,
		app.StepGAU,
		app.StepCTL,
		app.StepSubfinder,
		app.StepChaos,
	}
	s.mu.Lock()
	isRunning := s.running
	s.mu.Unlock()
	if !isRunning {
		allTerminal := true
		s.stepMu.Lock()
		for _, id := range subdomainStepIDs {
			st, ok := s.stepState[id]
			if !ok {
				allTerminal = false
				break
			}
			if st != app.StepDone && st != app.StepError && st != app.StepSkipped {
				allTerminal = false
				break
			}
		}
		s.stepMu.Unlock()
		if allTerminal {
			resp.OverallDone = total
			resp.OverallPercent = 100
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) leadsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uniqueLeads, latest, err := s.collectLeads()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var active []leadItem
	var hits []leadItem
	var investigation []leadItem
	var archive []leadItem
	totalROI := 0
	for _, lead := range uniqueLeads {
		totalROI += lead.ROI
		switch lead.Bucket {
		case "hits":
			hits = append(hits, lead)
		case "investigation":
			investigation = append(investigation, lead)
		case "archive":
			archive = append(archive, lead)
		default:
			active = append(active, lead)
		}
	}

	resp := leadsResponse{
		Present:                len(uniqueLeads) > 0,
		UpdatedAt:              latest.UTC().Format(time.RFC3339),
		TotalLeads:             len(uniqueLeads),
		TotalROI:               totalROI,
		Wildcards:              buildWildcardGroups(active),
		HitsWildcards:          buildWildcardGroups(hits),
		InvestigationWildcards: buildWildcardGroups(investigation),
		ArchiveWildcards:       buildWildcardGroups(archive),
		HitsCount:              len(hits),
		InvestigationCount:     len(investigation),
		ArchiveCount:           len(archive),
	}
	if latest.IsZero() {
		resp.UpdatedAt = ""
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) toolsHandler(w http.ResponseWriter, r *http.Request) {
	tools := []toolStatus{
		s.toolCheck("amass", true, ""),
		s.toolCheck("sublist3r", false, "optional; flow can continue without it"),
		s.toolCheck("assetfinder", true, ""),
		s.toolCheck("gau", true, ""),
		s.toolCheck("subfinder", true, ""),
		s.toolCheck("httpx", true, ""),
		s.toolCheck("ffuf", false, "needed for fuzz-docs/fuzz-dirs steps"),
		s.toolCheck("cewl", false, "optional; flow can continue without it"),
		s.toolCheck("nuclei", false, "optional; enables template-based vulnerability scan step"),
		s.toolCheck("httprobe", false, "used as fallback when httpx fails"),
		s.toolCheck("node", false, "required for manual Playwright XSS scan"),
	}

	missingRequired := 0
	for _, t := range tools {
		if t.Required && !t.Installed {
			missingRequired++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":               missingRequired == 0,
		"missing_required": missingRequired,
		"tools":            tools,
	})
}

func (s *Server) manualXSSStatusHandler(w http.ResponseWriter, r *http.Request) {
	s.xssMu.Lock()
	resp := manualXSSStatusResponse{
		Running: s.xssRunning,
		Status:  s.xssStatus,
		LastRun: s.xssLastRun,
	}
	s.xssMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) manualXSSRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req manualXSSRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		http.Error(w, "target must be a valid http(s) URL", http.StatusBadRequest)
		return
	}

	s.xssMu.Lock()
	if s.xssRunning {
		s.xssMu.Unlock()
		http.Error(w, "manual xss scan already running", http.StatusConflict)
		return
	}
	s.xssRunning = true
	s.xssStatus = "queued"
	s.xssMu.Unlock()

	go s.runManualPlaywrightXSS(target, strings.TrimSpace(req.AuthHeader))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) runManualPlaywrightXSS(target, authHeader string) {
	s.setManualXSSStatus("running")
	defer func() {
		s.xssMu.Lock()
		s.xssRunning = false
		s.xssLastRun = time.Now().Format(time.RFC3339)
		s.xssMu.Unlock()
	}()

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	outDir := filepath.Join(baseDir, "fuzzing", "xss")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		s.setManualXSSStatus(fmt.Sprintf("error: failed creating output dir: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	nodeBin, err := resolveNodeBinary()
	if err != nil {
		s.setManualXSSStatus("error: node runtime not found in PATH or ~/.nvm; install Node.js or restart server with nvm loaded")
		return
	}
	scriptPath := filepath.Join("scripts", "xss_playwright_scan.mjs")
	args := []string{scriptPath, "--target", target, "--out-dir", outDir, "--max-pages", "30", "--max-clicks", "140"}
	if authHeader != "" {
		args = append(args, "--auth-header", authHeader)
	}

	cmd := exec.CommandContext(ctx, nodeBin, args...)
	output, err := cmd.CombinedOutput()
	logPath := filepath.Join(outDir, "scan.log")
	_ = os.WriteFile(logPath, output, 0o644)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.setManualXSSStatus("error: playwright xss scan timed out")
			return
		}
		s.setManualXSSStatus(fmt.Sprintf("error: playwright scan failed (%v)", err))
		return
	}
	s.setManualXSSStatus("done")
}

func resolveNodeBinary() (string, error) {
	if path, err := exec.LookPath("node"); err == nil {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("unable to resolve home directory")
	}

	patterns := []string{
		filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "node"),
		filepath.Join(home, ".volta", "bin", "node"),
		filepath.Join(home, ".asdf", "shims", "node"),
	}
	var candidates []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		candidates = append(candidates, matches...)
	}
	sort.Strings(candidates)
	for i := len(candidates) - 1; i >= 0; i-- {
		candidate := candidates[i]
		info, statErr := os.Stat(candidate)
		if statErr != nil || info.IsDir() {
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", errors.New("node binary not found")
}

func (s *Server) setManualXSSStatus(status string) {
	s.xssMu.Lock()
	s.xssStatus = status
	s.xssMu.Unlock()
}

func (s *Server) toolCheck(name string, required bool, notes string) toolStatus {
	status := toolStatus{Name: name, Required: required, Notes: notes}
	if path, err := exec.LookPath(name); err == nil {
		status.Installed = true
		status.Path = path
	}
	return status
}

func (s *Server) recordLog(line string) {
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > 400 {
		s.logLines = s.logLines[len(s.logLines)-400:]
	}
}

func (s *Server) Write(p []byte) (int, error) {
	s.logMu.Lock()
	defer s.logMu.Unlock()

	lines := strings.Split(string(p), "\n")
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			continue
		}
		s.recordLog(strings.TrimRight(line, "\r"))
	}

	if strings.TrimSpace(s.logPath) != "" {
		if err := os.MkdirAll(filepath.Dir(s.logPath), 0o755); err == nil {
			if f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				_, _ = f.Write(p)
				_ = f.Close()
			}
		}
	}
	return len(p), nil
}

func (s *Server) loadPersistedLogs() {
	if strings.TrimSpace(s.logPath) == "" {
		return
	}
	lines, err := readLastLines(s.logPath, 400)
	if err != nil {
		return
	}
	s.logMu.Lock()
	s.logLines = lines
	s.logMu.Unlock()
}

func readLastLines(path string, max int) ([]string, error) {
	if max <= 0 {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	all := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	filtered := make([]string, 0, len(all))
	for _, line := range all {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	if len(filtered) <= max {
		return filtered, nil
	}
	return filtered[len(filtered)-max:], nil
}

func (s *Server) initSteps() {
	s.steps = app.FlowSteps()
	s.stepState = make(map[string]app.StepStatus, len(s.steps))
	for _, step := range s.steps {
		s.stepState[step.ID] = app.StepPending
	}
	s.loadPersistedStepState()
	s.inferCompletedStepsFromArtifacts()
}

func (s *Server) resetSteps() {
	s.resetStepsInMemory()
	s.persistStepState()
}

func (s *Server) resetStepsInMemory() {
	s.stepMu.Lock()
	for _, step := range s.steps {
		s.stepState[step.ID] = app.StepPending
	}
	s.stepMu.Unlock()
}

func (s *Server) updateStep(id string, status app.StepStatus) {
	s.stepMu.Lock()
	if _, ok := s.stepState[id]; ok {
		s.stepState[id] = status
	}
	s.stepMu.Unlock()
	s.persistStepState()
}

func (s *Server) markPendingStepsSkipped() {
	s.stepMu.Lock()
	changed := false
	for id, st := range s.stepState {
		if st == app.StepPending {
			s.stepState[id] = app.StepSkipped
			changed = true
		}
	}
	s.stepMu.Unlock()
	if changed {
		s.persistStepState()
	}
}

func (s *Server) loadPersistedStepState() {
	if s.stepsPath == "" {
		return
	}
	raw, err := os.ReadFile(s.stepsPath)
	if err != nil {
		return
	}
	var snapshot map[string]app.StepStatus
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return
	}
	s.stepMu.Lock()
	for _, step := range s.steps {
		if st, ok := snapshot[step.ID]; ok {
			if st == app.StepRunning {
				st = app.StepPending
			}
			s.stepState[step.ID] = st
		}
	}
	s.stepMu.Unlock()
}

func (s *Server) persistStepState() {
	if s.stepsPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.stepsPath), 0o755); err != nil {
		return
	}
	s.stepMu.Lock()
	snapshot := make(map[string]app.StepStatus, len(s.stepState))
	for k, v := range s.stepState {
		snapshot[k] = v
	}
	s.stepMu.Unlock()
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.stepsPath, raw, 0o644)
}

func (s *Server) inferCompletedStepsFromArtifacts() {
	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	amassDir := filepath.Join(reconDir, "amass")
	rawDir := filepath.Join(reconDir, "raw")

	hasAnyScope := len(readListLines(s.cfg.Lists.Organizations)) > 0 ||
		len(readListLines(s.cfg.Lists.Wildcards)) > 0 ||
		len(readListLines(s.cfg.Lists.Domains)) > 0 ||
		len(readListLines(s.cfg.Lists.APIDomains)) > 0 ||
		len(readListLines(s.cfg.Lists.IPs)) > 0

	doneIfPending := func(id string, cond bool) {
		if !cond {
			return
		}
		s.stepMu.Lock()
		if s.stepState[id] == app.StepPending {
			s.stepState[id] = app.StepDone
		}
		s.stepMu.Unlock()
	}

	doneIfPending("load-config", true)
	doneIfPending("validate-inputs", hasAnyScope)
	doneIfPending("subdomain-enumeration", fileHasNonEmpty(s.cfg.Lists.Domains))
	doneIfPending("amass", dirHasNonEmptyExt(amassDir, ".txt"))
	doneIfPending("sublist3r",
		dirHasExt(filepath.Join(rawDir, "sublist3r"), ".txt") ||
			globHasAny(filepath.Join(reconDir, "sublist3r_*.txt")),
	)
	doneIfPending("assetfinder",
		dirHasExt(filepath.Join(rawDir, "assetfinder"), ".txt") ||
			globHasAny(filepath.Join(reconDir, "assetfinder_*.txt")),
	)
	doneIfPending("gau",
		dirHasExt(filepath.Join(rawDir, "gau"), ".txt") ||
			globHasAny(filepath.Join(reconDir, "gau_*.txt")),
	)
	doneIfPending("ctl",
		dirHasExt(filepath.Join(rawDir, "ctl"), ".json") ||
			globHasAny(filepath.Join(reconDir, "ctl_*.json")),
	)
	doneIfPending("subfinder",
		dirHasExt(filepath.Join(rawDir, "subfinder"), ".txt") ||
			globHasAny(filepath.Join(reconDir, "subfinder_*.txt")),
	)
	doneIfPending("chaos",
		dirHasExt(filepath.Join(rawDir, "chaos"), ".json"),
	)
	doneIfPending("persist-raw-outputs",
		fileExists(amassDir) &&
			fileExists(filepath.Join(rawDir, "amass")) &&
			fileExists(filepath.Join(rawDir, "sublist3r")) &&
			fileExists(filepath.Join(rawDir, "assetfinder")) &&
			fileExists(filepath.Join(rawDir, "gau")) &&
			fileExists(filepath.Join(rawDir, "ctl")) &&
			fileExists(filepath.Join(rawDir, "subfinder")) &&
			fileExists(filepath.Join(rawDir, "chaos")),
	)
	doneIfPending("dnsx-validate",
		fileExists(filepath.Join(rawDir, "dnsx-validate", "validated_hosts.txt")) ||
			fileExists(filepath.Join(reconDir, "dnsx_validated_hosts.txt")),
	)
	doneIfPending("consolidate", fileHasNonEmpty(s.cfg.Lists.Domains))
	doneIfPending("httpx",
		fileHasNonEmpty(filepath.Join(baseDir, "live-webservers.jsonl")) ||
			fileHasNonEmpty(filepath.Join(baseDir, "domains_http")),
	)
	doneIfPending("robots-sitemaps",
		fileExists(filepath.Join(s.cfg.Paths.RobotsDir, "robots_urls.txt")) ||
			fileExists(filepath.Join(s.cfg.Paths.RobotsDir, "_hits.txt")) ||
			fileExists(s.cfg.Paths.SitemapsFile),
	)
	doneIfPending("waybackurls",
		fileExists(filepath.Join(reconDir, "waybackurls_urls.txt")) ||
			fileExists(filepath.Join(reconDir, "urls_waybackurls.txt")),
	)
	doneIfPending("katana",
		fileExists(filepath.Join(reconDir, "katana_urls.txt")) ||
			fileExists(filepath.Join(reconDir, "urls_katana.txt")),
	)
	doneIfPending("url-corpus",
		fileExists(filepath.Join(reconDir, "all_urls.txt")) ||
			fileExists(filepath.Join(reconDir, "urls_all.txt")),
	)
	doneIfPending("param-fuzz",
		fileExists(filepath.Join(baseDir, "fuzzing", "params", "query_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "params", "body_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "params", "header_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "params", "cookie_hits.jsonl")),
	)
	doneIfPending("injection-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "injection", "sqli_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "injection", "nosqli_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "injection", "xpath_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "injection", "ldap_hits.jsonl")),
	)
	doneIfPending("server-input-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "server-input", "os_command_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "server-input", "path_traversal_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "server-input", "file_inclusion_hits.jsonl")),
	)
	doneIfPending("adv-injection-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "adv-injection", "xxe_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "adv-injection", "soap_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "adv-injection", "ssrf_hits.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "adv-injection", "smtp_hits.jsonl")),
	)
	doneIfPending("csrf-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "csrf", "candidates.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "csrf", "findings.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "csrf", "replay_log.jsonl")),
	)
	doneIfPending("clickjacking-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "clickjacking", "headers.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "clickjacking", "findings.jsonl")),
	)
	doneIfPending("cors-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "cors", "replay_log.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "cors", "findings.jsonl")),
	)
	doneIfPending("open-redirect-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "open-redirect", "candidates.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "open-redirect", "findings.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "open-redirect", "replay_log.jsonl")),
	)
	doneIfPending("workflow-logic-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "workflow-logic", "candidates.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "workflow-logic", "findings.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "workflow-logic", "replay_log.jsonl")),
	)
	doneIfPending("smuggling-stack-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "smuggling-stack", "tool_runs.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "smuggling-stack", "findings.jsonl")),
	)
	doneIfPending("nmap-enrichment-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "nmap", "targets.txt")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "nmap", "services.csv")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "nmap", "searchsploit.txt")),
	)
	doneIfPending("nuclei-scan", fileExists(filepath.Join(baseDir, "fuzzing", "nuclei", "findings.jsonl")))
	doneIfPending("tier-isolation-checks",
		fileExists(filepath.Join(baseDir, "fuzzing", "tier-isolation", "ip_map.jsonl")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "tier-isolation", "findings.jsonl")),
	)
	doneIfPending("static-review-correlation",
		fileExists(filepath.Join(baseDir, "fuzzing", "static-review", "semgrep.json")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "static-review", "gosec.json")) ||
			fileExists(filepath.Join(baseDir, "fuzzing", "static-review", "correlated_findings.jsonl")),
	)
	doneIfPending("runops-manifest-export", globHasNonEmpty(filepath.Join(s.cfg.Paths.LogsDir, "runops", "manifest_*.json")))
	doneIfPending("stage-gates-scorecard", fileExists(filepath.Join(s.cfg.Paths.LogsDir, "runops", "scorecard.json")))
	doneIfPending("dork-links", hasDorkLinkFiles(s.cfg.Paths.DorkingDir))
	doneIfPending("cewl",
		fileExists(filepath.Join(reconDir, "cewl_custom_wordlist.txt")) ||
			fileExists(filepath.Join(baseDir, "cewl_custom_wordlist.txt")),
	)
	doneIfPending("fuzz-docs", fileExists(filepath.Join(baseDir, "fuzzing", "documentation", "doc_hits.txt")))
	doneIfPending("fuzz-dirs", fileExists(filepath.Join(baseDir, "fuzzing", "ffuf", "dir_hits.txt")))
}

func (s *Server) initConfigStore() {
	path := os.Getenv("BFLOW_CONFIG_PATH")
	if strings.TrimSpace(path) == "" {
		path = filepath.Join("data", "config.json")
	}
	store, err := configstore.New(path)
	if err != nil {
		s.logger.Printf("config store disabled: %v", err)
		return
	}
	s.configStore = store
	s.loadProxySettings()
	s.applyNetworkSettingsToApp()
}

func (s *Server) loadTorEnabled() bool {
	if s.configStore == nil {
		return s.torEnabled
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		return s.torEnabled
	}
	network := cfg.Providers["network"]
	if network == nil {
		return s.torEnabled
	}
	return network.AutoRun
}

func (s *Server) startFlow() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("flow already running")
	}
	if missing := s.missingRequiredToolsForRun(); len(missing) > 0 {
		return fmt.Errorf("missing required tools for run: %s", strings.Join(missing, ", "))
	}

	resume := s.paused
	s.running = true
	s.abortMode = ""
	if resume {
		s.status = "running (resumed)"
	} else {
		s.status = "running"
		s.resetSteps()
	}
	torEnabled := s.loadTorEnabled()
	doneSteps := make(map[string]bool)
	if resume {
		s.inferCompletedStepsFromArtifacts()
		s.stepMu.Lock()
		for stepID, status := range s.stepState {
			if status == app.StepDone {
				doneSteps[stepID] = true
			}
		}
		s.stepMu.Unlock()
	}
	if s.app != nil {
		s.applyNetworkSettingsToApp()
		s.app.SetResumeCompleted(doneSteps)
	}
	s.paused = false
	s.torProbe = app.EgressProbe{}
	s.torProbeAt = ""

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.runCancel = cancel
		s.mu.Unlock()

		defer func() {
			cancel()
			s.mu.Lock()
			mode := s.abortMode
			s.running = false
			s.runCancel = nil
			now := time.Now().Format(time.RFC3339)
			switch mode {
			case "pause":
				s.paused = true
				s.status = fmt.Sprintf("paused at %s", now)
			case "stop":
				s.paused = false
				s.status = fmt.Sprintf("stopped at %s", now)
			default:
				s.paused = false
				s.status = fmt.Sprintf("last run finished at %s", now)
			}
			s.abortMode = ""
			s.mu.Unlock()
		}()

		if torEnabled {
			s.refreshTorProbe(ctx)
		}

		if err := s.app.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			s.mu.Lock()
			mode := s.abortMode
			s.mu.Unlock()
			if mode == "pause" || mode == "stop" {
				return
			}
			s.markPendingStepsSkipped()
			s.logger.Printf("flow run failed: %v", err)
			s.mu.Lock()
			s.status = fmt.Sprintf("error: %v", err)
			s.mu.Unlock()
		}
	}()

	return nil
}

func (s *Server) requestStop(pause bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.runCancel == nil {
		return errors.New("flow is not running")
	}
	if pause {
		s.abortMode = "pause"
		s.status = "pausing..."
	} else {
		s.abortMode = "stop"
		s.status = "stopping..."
		s.paused = false
	}
	s.runCancel()
	return nil
}

func (s *Server) clearResults() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("cannot clear results while flow is running")
	}
	s.paused = false
	s.abortMode = ""
	s.status = "idle"
	s.logMu.Lock()
	s.logLines = nil
	s.logMu.Unlock()
	if strings.TrimSpace(s.logPath) != "" {
		_ = os.MkdirAll(filepath.Dir(s.logPath), 0o755)
		_ = os.WriteFile(s.logPath, []byte{}, 0o644)
	}
	s.mu.Unlock()

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	targets := []string{
		filepath.Join(baseDir, "recon"),
		filepath.Join(baseDir, "fuzzing"),
		s.cfg.Paths.RobotsDir,
		s.cfg.Paths.DorkingDir,
		filepath.Join(s.cfg.Paths.LogsDir, "runops"),
		filepath.Join(baseDir, "live-webservers.jsonl"),
		s.cfg.Paths.SitemapsFile,
		"robots",
		"fuzzing",
		"logs",
	}
	for _, path := range targets {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if isSourceDir(path) {
			continue
		}
		_ = os.RemoveAll(path)
	}

	// Remove generated scope outputs entirely; they will be recreated by relevant steps.
	for _, generatedList := range []string{
		s.cfg.Lists.Domains,
		filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "domains_resolved"),
		filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "domains_http"),
		filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "domains_dead"),
		s.cfg.Lists.APIDomains,
		filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "apidomains_http"),
		filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "apidomains_dead"),
		s.cfg.Lists.IPs,
	} {
		if strings.TrimSpace(generatedList) == "" {
			continue
		}
		_ = os.Remove(generatedList)
	}
	if strings.TrimSpace(s.stepsPath) != "" {
		_ = os.Remove(s.stepsPath)
	}
	s.resetStepsInMemory()
	s.torProbe = app.EgressProbe{}
	s.torProbeAt = ""
	return nil
}

func isSourceDir(path string) bool {
	clean := filepath.Clean(path)
	switch clean {
	case ".", "ui", "pkg", "cmd", "scripts", "dorking", "utils", "resources", "__dev", "_notes":
		return true
	default:
		return false
	}
}

func (s *Server) refreshTorProbe(parent context.Context) {
	if s.app == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 18*time.Second)
	defer cancel()
	probe := s.app.ProbeNetworkEgress(ctx)
	now := time.Now().Format(time.RFC3339)
	s.mu.Lock()
	s.torProbe = probe
	s.torProbeAt = now
	s.mu.Unlock()
	if probe.IP != "" {
		s.logger.Printf("tor egress check: mode=%s ip=%s source=%s", probe.Mode, probe.IP, probe.Source)
		return
	}
	s.logger.Printf("tor egress check: mode=%s error=%s", probe.Mode, probe.Error)
}

func (s *Server) missingRequiredToolsForRun() []string {
	// Subdomain discovery pipeline only runs when wildcards are provided.
	if len(readListLines(s.cfg.Lists.Wildcards)) == 0 {
		return nil
	}

	enabled := s.loadSubdomainToolSettings()
	required := []string{}
	if enabled["amass"] {
		required = append(required, "amass")
	}
	if enabled["assetfinder"] {
		required = append(required, "assetfinder")
	}
	if enabled["gau"] {
		required = append(required, "gau")
	}
	if enabled["subfinder"] {
		required = append(required, "subfinder")
	}
	if len(required) > 0 {
		required = append(required, "httpx")
	}
	var missing []string
	for _, name := range required {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

func (s *Server) loadSubdomainToolSettings() map[string]bool {
	settings := map[string]bool{
		"amass":       true,
		"sublist3r":   true,
		"assetfinder": true,
		"gau":         true,
		"ctl":         true,
		"subfinder":   true,
		"chaos":       true,
	}
	if s.configStore == nil {
		return settings
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		return settings
	}
	for tool := range settings {
		if provider := cfg.Providers[tool]; provider != nil {
			settings[tool] = provider.AutoRun
		}
	}
	return settings
}

func (s *Server) listPath(name string) (string, error) {
	switch strings.ToLower(name) {
	case "organizations":
		return s.cfg.Lists.Organizations, nil
	case "ips":
		return s.cfg.Lists.IPs, nil
	case "wildcards":
		return s.cfg.Lists.Wildcards, nil
	case "domains":
		return s.cfg.Lists.Domains, nil
	case "domains_http":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "domains_http"), nil
	case "domains_dead":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "domains_dead"), nil
	case "apidomains":
		return s.cfg.Lists.APIDomains, nil
	case "apidomains_http":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "apidomains_http"), nil
	case "apidomains_dead":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "apidomains_dead"), nil
	case "out_of_scope":
		return s.cfg.Lists.OutOfScope, nil
	case "fuzzing_doc_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "documentation", "doc_hits.txt"), nil
	case "fuzzing_dir_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "ffuf", "dir_hits.txt"), nil
	case "robots_urls":
		return filepath.Join(s.cfg.Paths.RobotsDir, "robots_urls.txt"), nil
	case "wayback_urls":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "waybackurls_urls.txt"), nil
	case "katana_urls":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "katana_urls.txt"), nil
	case "all_urls":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "all_urls.txt"), nil
	case "params_candidates":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "recon", "params_candidates.txt"), nil
	case "param_fuzz_query_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "params", "query_hits.jsonl"), nil
	case "param_fuzz_body_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "params", "body_hits.jsonl"), nil
	case "param_fuzz_header_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "params", "header_hits.jsonl"), nil
	case "param_fuzz_cookie_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "params", "cookie_hits.jsonl"), nil
	case "injection_sqli_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "sqli_hits.jsonl"), nil
	case "injection_nosqli_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "nosqli_hits.jsonl"), nil
	case "injection_xpath_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "xpath_hits.jsonl"), nil
	case "injection_ldap_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "ldap_hits.jsonl"), nil
	case "server_input_os_command_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "os_command_hits.jsonl"), nil
	case "server_input_path_traversal_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "path_traversal_hits.jsonl"), nil
	case "server_input_file_inclusion_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "file_inclusion_hits.jsonl"), nil
	case "adv_injection_xxe_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "xxe_hits.jsonl"), nil
	case "adv_injection_soap_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "soap_hits.jsonl"), nil
	case "adv_injection_ssrf_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "ssrf_hits.jsonl"), nil
	case "adv_injection_smtp_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "smtp_hits.jsonl"), nil
	case "csrf_candidates":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "csrf", "candidates.jsonl"), nil
	case "csrf_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "csrf", "findings.jsonl"), nil
	case "csrf_replay_log":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "csrf", "replay_log.jsonl"), nil
	case "clickjacking_headers":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "clickjacking", "headers.jsonl"), nil
	case "clickjacking_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "clickjacking", "findings.jsonl"), nil
	case "cors_replay_log":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "cors", "replay_log.jsonl"), nil
	case "cors_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "cors", "findings.jsonl"), nil
	case "open_redirect_candidates":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "open-redirect", "candidates.jsonl"), nil
	case "open_redirect_replay_log":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "open-redirect", "replay_log.jsonl"), nil
	case "open_redirect_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "open-redirect", "findings.jsonl"), nil
	case "workflow_logic_candidates":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "workflow-logic", "candidates.jsonl"), nil
	case "workflow_logic_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "workflow-logic", "findings.jsonl"), nil
	case "workflow_logic_replay_log":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "workflow-logic", "replay_log.jsonl"), nil
	case "smuggling_stack_tool_runs":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "smuggling-stack", "tool_runs.jsonl"), nil
	case "smuggling_stack_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "smuggling-stack", "findings.jsonl"), nil
	case "nmap_targets":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "nmap", "targets.txt"), nil
	case "nmap_services":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "nmap", "services.csv"), nil
	case "nmap_searchsploit":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "nmap", "searchsploit.txt"), nil
	case "nuclei_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "nuclei", "findings.jsonl"), nil
	case "tier_isolation_ip_map":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "tier-isolation", "ip_map.jsonl"), nil
	case "tier_isolation_findings":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "tier-isolation", "findings.jsonl"), nil
	case "static_review_semgrep":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "static-review", "semgrep.json"), nil
	case "static_review_gosec":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "static-review", "gosec.json"), nil
	case "static_review_correlated":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "static-review", "correlated_findings.jsonl"), nil
	case "runops_scorecard_json":
		return filepath.Join(s.cfg.Paths.LogsDir, "runops", "scorecard.json"), nil
	case "runops_scorecard_md":
		return filepath.Join(s.cfg.Paths.LogsDir, "runops", "scorecard.md"), nil
	case "xss_reflected_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "xss", "reflected_hits.jsonl"), nil
	case "xss_dom_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "xss", "dom_hits.jsonl"), nil
	case "xss_stored_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "xss", "stored_hits.jsonl"), nil
	case "xss_scan_log":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "xss", "scan.log"), nil
	default:
		return "", fmt.Errorf("unsupported list_type %q", name)
	}
}

func (s *Server) saveTemporaryFile(dest string, src io.Reader) error {
	if dest == "" {
		return errors.New("destination path is empty")
	}
	dir := filepath.Dir(dest)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	tmp := dest + ".upload"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, src); err != nil {
		return err
	}

	if err := os.Rename(tmp, dest); err != nil {
		return err
	}

	return nil
}

func readListLines(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func readLiveWebserversJSONL(path string) ([]liveWebserverRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []liveWebserverRow
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row liveWebserverRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		out = append(out, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func readAmassEnumJSONL(path string) ([]amassEnumRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var rows []amassEnumRow
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		name := strings.TrimSpace(asRawString(raw["name"]))
		if name == "" {
			continue
		}
		domain := strings.TrimSpace(asRawString(raw["domain"]))
		source := strings.TrimSpace(asRawString(raw["source"]))
		tag := strings.TrimSpace(asRawString(raw["tag"]))
		addresses, _ := raw["addresses"].([]any)
		if len(addresses) == 0 {
			key := strings.Join([]string{name, domain, "", "0", source, tag}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rows = append(rows, amassEnumRow{Name: name, Domain: domain, Source: source, Tag: tag})
			continue
		}

		for _, addr := range addresses {
			addrMap, ok := addr.(map[string]any)
			if !ok {
				continue
			}
			ip := strings.TrimSpace(asRawString(addrMap["ip"]))
			asn := asRawInt(addrMap["asn"])
			key := strings.Join([]string{name, domain, ip, strconv.Itoa(asn), source, tag}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rows = append(rows, amassEnumRow{
				Name:   name,
				Domain: domain,
				IP:     ip,
				ASN:    asn,
				Source: source,
				Tag:    tag,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func readAmassEnumFromSeedText(dir string) ([]amassEnumRow, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var rows []amassEnumRow
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if !strings.HasSuffix(strings.ToLower(name), ".txt") {
			continue
		}
		seed := strings.TrimSpace(strings.TrimSuffix(name, filepath.Ext(name)))
		if seed == "" {
			continue
		}
		path := filepath.Join(dir, name)
		seedRows, parseErr := parseAmassSeedText(path, seed)
		if parseErr != nil {
			continue
		}
		rows = append(rows, seedRows...)
	}

	return rows, nil
}

func parseAmassSeedText(path string, seed string) ([]amassEnumRow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	seed = strings.ToLower(strings.TrimSpace(seed))
	hostIPs := make(map[string]map[string]struct{})
	ipNetblocks := make(map[string]map[string]struct{})
	netblockASN := make(map[string]int)
	hostSeen := make(map[string]struct{})

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "-->") {
			continue
		}
		left, rel, right, ok := parseAmassRelationLine(line)
		if !ok {
			continue
		}
		leftVal := strings.ToLower(strings.TrimSpace(left.value))
		rightVal := strings.ToLower(strings.TrimSpace(right.value))
		if left.typ == "fqdn" {
			hostSeen[leftVal] = struct{}{}
		}
		if left.typ == "fqdn" && (rel == "a_record" || rel == "aaaa_record") && right.typ == "ipaddress" {
			if hostIPs[leftVal] == nil {
				hostIPs[leftVal] = make(map[string]struct{})
			}
			hostIPs[leftVal][rightVal] = struct{}{}
			continue
		}
		if left.typ == "netblock" && rel == "contains" && right.typ == "ipaddress" {
			if ipNetblocks[rightVal] == nil {
				ipNetblocks[rightVal] = make(map[string]struct{})
			}
			ipNetblocks[rightVal][leftVal] = struct{}{}
			continue
		}
		if left.typ == "asn" && rel == "announces" && right.typ == "netblock" {
			asn, convErr := strconv.Atoi(strings.TrimSpace(left.value))
			if convErr == nil {
				netblockASN[rightVal] = asn
			}
		}
	}

	allHosts := make([]string, 0, len(hostSeen))
	for host := range hostSeen {
		allHosts = append(allHosts, host)
	}
	sort.Strings(allHosts)

	var rows []amassEnumRow
	for _, host := range allHosts {
		ipSet := hostIPs[host]
		if len(ipSet) == 0 {
			rows = append(rows, amassEnumRow{
				Name:   host,
				Domain: seed,
				Source: "amass",
			})
			continue
		}
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			asn := 0
			if blocks := ipNetblocks[ip]; len(blocks) > 0 {
				for block := range blocks {
					if val, ok := netblockASN[block]; ok && val != 0 {
						asn = val
						break
					}
				}
			}
			rows = append(rows, amassEnumRow{
				Name:   host,
				Domain: seed,
				IP:     ip,
				ASN:    asn,
				Source: "amass",
			})
		}
	}

	return rows, nil
}

type amassEntity struct {
	value string
	typ   string
}

func parseAmassRelationLine(line string) (amassEntity, string, amassEntity, bool) {
	parts := strings.Split(line, "-->")
	if len(parts) != 3 {
		return amassEntity{}, "", amassEntity{}, false
	}
	left, okLeft := parseAmassEntity(parts[0])
	right, okRight := parseAmassEntity(parts[2])
	if !okLeft || !okRight {
		return amassEntity{}, "", amassEntity{}, false
	}
	rel := strings.ToLower(strings.TrimSpace(parts[1]))
	if rel == "" {
		return amassEntity{}, "", amassEntity{}, false
	}
	return left, rel, right, true
}

func parseAmassEntity(raw string) (amassEntity, bool) {
	raw = strings.TrimSpace(raw)
	open := strings.LastIndex(raw, "(")
	close := strings.LastIndex(raw, ")")
	if open < 0 || close < 0 || close <= open {
		return amassEntity{}, false
	}
	val := strings.TrimSpace(raw[:open])
	typ := strings.ToLower(strings.TrimSpace(raw[open+1 : close]))
	if val == "" || typ == "" {
		return amassEntity{}, false
	}
	return amassEntity{value: val, typ: typ}, true
}

func normalizeAmassRows(rows []amassEnumRow) []amassEnumRow {
	type aggRow struct {
		row    amassEnumRow
		hasIP  bool
		hasASN bool
		hasSrc bool
		hasTag bool
	}
	agg := make(map[string]aggRow, len(rows))
	for _, row := range rows {
		name := strings.ToLower(strings.TrimSpace(row.Name))
		domain := strings.ToLower(strings.TrimSpace(row.Domain))
		ip := strings.TrimSpace(row.IP)
		source := strings.TrimSpace(row.Source)
		tag := strings.TrimSpace(row.Tag)
		if name == "" {
			continue
		}
		key := strings.Join([]string{name, domain, ip}, "|")
		item := agg[key]
		if item.row.Name == "" {
			item.row = amassEnumRow{
				Name:   name,
				Domain: domain,
				IP:     ip,
			}
		}
		if ip != "" {
			item.hasIP = true
			item.row.IP = ip
		}
		if row.ASN != 0 {
			item.hasASN = true
			item.row.ASN = row.ASN
		}
		if source != "" && !item.hasSrc {
			item.row.Source = source
			item.hasSrc = true
		}
		if tag != "" && !item.hasTag {
			item.row.Tag = tag
			item.hasTag = true
		}
		agg[key] = item
	}

	out := make([]amassEnumRow, 0, len(agg))
	for _, item := range agg {
		out = append(out, item.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain == out[j].Domain {
			if out[i].Name == out[j].Name {
				return out[i].IP < out[j].IP
			}
			return out[i].Name < out[j].Name
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

func (s *Server) syncIPsFromAmassRows(rows []amassEnumRow) {
	if strings.TrimSpace(s.cfg.Lists.IPs) == "" || len(rows) == 0 {
		return
	}
	all := make([]string, 0, len(rows))
	for _, existing := range readListLines(s.cfg.Lists.IPs) {
		all = append(all, existing)
	}
	for _, row := range rows {
		all = append(all, row.IP)
	}
	ips := sortedUniqueIPs(all)
	if len(ips) == 0 {
		return
	}
	_ = os.WriteFile(s.cfg.Lists.IPs, []byte(strings.Join(ips, "\n")), 0o644)
}

func sortedUniqueIPs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		ip := net.ParseIP(strings.TrimSpace(v))
		if ip == nil {
			continue
		}
		canonical := ip.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipStringLess(out[i], out[j])
	})
	return out
}

func ipStringLess(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return a < b
	}
	a4 := ipa.To4()
	b4 := ipb.To4()
	if a4 != nil && b4 == nil {
		return true
	}
	if a4 == nil && b4 != nil {
		return false
	}
	aa := ipa.To16()
	bb := ipb.To16()
	if aa == nil || bb == nil {
		return a < b
	}
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] == bb[i] {
			continue
		}
		return aa[i] < bb[i]
	}
	return a < b
}

func readDNSXHostIPs(path string) map[string][]string {
	out := make(map[string][]string)
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(fields[0]))
		if host == "" {
			continue
		}
		seenIPs := make(map[string]struct{})
		for _, token := range fields[1:] {
			clean := strings.Trim(token, "[],;()")
			if ip := net.ParseIP(clean); ip != nil {
				seenIPs[ip.String()] = struct{}{}
			}
		}
		for ip := range seenIPs {
			out[host] = append(out[host], ip)
		}
		sort.Strings(out[host])
	}
	return out
}

func uniqueNormalizedSeeds(lines []string) []string {
	set := make(map[string]struct{})
	for _, line := range lines {
		seed := strings.ToLower(strings.TrimSpace(line))
		seed = strings.TrimPrefix(seed, "*.")
		seed = strings.TrimPrefix(seed, ".")
		if seed == "" {
			continue
		}
		set[seed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for seed := range set {
		out = append(out, seed)
	}
	sort.Strings(out)
	return out
}

func countFilesByExt(dir string, ext string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	want := strings.ToLower(strings.TrimSpace(ext))
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if want != "" && !strings.HasSuffix(name, want) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		count++
	}
	return count
}

func readJSONLRecords(path string) ([]map[string]any, time.Time) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, time.Time{}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	records := []map[string]any{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		records = append(records, row)
	}
	return records, info.ModTime()
}

func buildLeadItem(category, source string, row map[string]any, roots []string) leadItem {
	target := strings.TrimSpace(firstNonEmptyString(
		asRawString(row["endpoint"]),
		asRawString(row["url"]),
		asRawString(row["mutated_url"]),
	))
	if target == "" {
		return leadItem{}
	}
	host := extractHost(target)
	if host == "" {
		return leadItem{}
	}
	domain := strings.ToLower(strings.TrimSpace(host))
	wildcard := matchWildcard(domain, roots)
	if wildcard == "" {
		wildcard = guessWildcardFromDomain(domain)
	}

	family := strings.TrimSpace(firstNonEmptyString(asRawString(row["family"]), asRawString(row["mode"])))
	severity := strings.ToLower(strings.TrimSpace(asRawString(row["severity"])))
	if severity == "" {
		severity = deriveSeverity(category, row)
	}
	reasons := asStringSlice(row["reasons"])
	manualAction := strings.TrimSpace(asRawString(row["manual_action"]))
	roi := computeLeadROI(category, severity, reasons, row)

	id := strings.ToLower(strings.TrimSpace(strings.Join([]string{
		category,
		family,
		domain,
		asRawString(row["param"]),
		asRawString(row["payload"]),
		target,
		strings.Join(reasons, "|"),
	}, "|")))
	if id == "||||||" || id == "" {
		return leadItem{}
	}
	return leadItem{
		ID:           id,
		Category:     category,
		Family:       family,
		Severity:     severity,
		ROI:          roi,
		Wildcard:     wildcard,
		Domain:       domain,
		Target:       target,
		Reasons:      reasons,
		ManualAction: manualAction,
		Evidence:     leadEvidence(row),
		Source:       source,
		Timestamp:    strings.TrimSpace(asRawString(row["timestamp"])),
	}
}

func leadEvidence(row map[string]any) map[string]any {
	if len(row) == 0 {
		return nil
	}
	preferred := []string{
		"mode",
		"family",
		"severity",
		"method",
		"endpoint",
		"url",
		"param",
		"payload",
		"vector",
		"mutated_url",
		"status_code",
		"baseline_status_code",
		"mutated_status_code",
		"length",
		"baseline_length",
		"mutated_length",
		"duration_ms",
		"baseline_duration_ms",
		"mutated_duration_ms",
		"baseline_location",
		"mutated_location",
		"origin",
		"referer",
		"chain_signals",
		"matcher-name",
		"template-id",
		"template",
		"matched-at",
		"host",
		"ip",
		"port",
		"timestamp",
	}
	out := make(map[string]any)
	for _, key := range preferred {
		if value, ok := row[key]; ok && !isLeadEvidenceEmpty(value) {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isLeadEvidenceEmpty(v any) bool {
	switch value := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(value) == ""
	case []any:
		return len(value) == 0
	case []string:
		return len(value) == 0
	case map[string]any:
		return len(value) == 0
	default:
		return false
	}
}

func deriveSeverity(category string, row map[string]any) string {
	status := asRawInt(row["status_code"])
	reasons := strings.ToLower(strings.Join(asStringSlice(row["reasons"]), " "))
	switch category {
	case "server-input":
		if strings.Contains(reasons, "family_keyword") || strings.Contains(reasons, "server_error_on_payload") {
			return "high"
		}
		return "medium"
	case "injection", "adv-injection":
		if strings.Contains(reasons, "family_keyword") || status >= 500 {
			return "high"
		}
		return "medium"
	case "open-redirect":
		chain := strings.Join(asStringSlice(row["chain_signals"]), ",")
		if strings.TrimSpace(chain) != "" {
			return "high"
		}
		return "medium"
	case "cors":
		if strings.Contains(reasons, "credentials_allowed") &&
			(strings.Contains(reasons, "arbitrary_origin_reflection") || strings.Contains(reasons, "wildcard_acao")) {
			return "high"
		}
		return "medium"
	case "csrf":
		if strings.Contains(reasons, "cross_origin_request_accepted") || strings.Contains(reasons, "missing_origin_referer_accepted") {
			return "high"
		}
		return "medium"
	case "clickjacking":
		if strings.Contains(reasons, "missing_x_frame_options") && strings.Contains(reasons, "missing_csp_frame_ancestors") {
			return "high"
		}
		return "medium"
	case "xss":
		if strings.Contains(strings.ToLower(asRawString(row["mode"])), "stored") || strings.Contains(strings.ToLower(asRawString(row["family"])), "stored") {
			return "high"
		}
		return "medium"
	default:
		return "low"
	}
}

func computeLeadROI(category, severity string, reasons []string, row map[string]any) int {
	base := map[string]int{"critical": 100, "high": 85, "medium": 55, "low": 30}[severity]
	if base == 0 {
		base = 35
	}
	categoryBoost := map[string]int{
		"injection":     18,
		"server-input":  24,
		"adv-injection": 20,
		"csrf":          16,
		"clickjacking":  10,
		"cors":          22,
		"open-redirect": 22,
		"xss":           20,
	}[category]
	score := base + categoryBoost
	reasonText := strings.ToLower(strings.Join(reasons, " "))
	if strings.Contains(reasonText, "family_keyword") {
		score += 10
	}
	if strings.Contains(reasonText, "server_error_on_payload") {
		score += 8
	}
	if strings.Contains(reasonText, "cross_origin_request_accepted") || strings.Contains(reasonText, "arbitrary_origin_reflection") {
		score += 12
	}
	if strings.Contains(reasonText, "credentials_allowed") {
		score += 12
	}
	if len(asStringSlice(row["chain_signals"])) > 0 {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	if score < 1 {
		score = 1
	}
	return score
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func extractHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	candidate := strings.TrimSpace(raw)
	if strings.Contains(candidate, "://") {
		return ""
	}
	if strings.Contains(candidate, "/") {
		candidate = strings.Split(candidate, "/")[0]
	}
	if strings.Contains(candidate, ":") {
		candidate = strings.Split(candidate, ":")[0]
	}
	return strings.TrimSpace(candidate)
}

func matchWildcard(domain string, roots []string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	best := ""
	for _, root := range roots {
		root = strings.ToLower(strings.TrimSpace(root))
		if root == "" {
			continue
		}
		if strings.HasPrefix(root, "*.") {
			root = strings.TrimPrefix(root, "*.")
		}
		if domain == root || strings.HasSuffix(domain, "."+root) {
			if len(root) > len(best) {
				best = root
			}
		}
	}
	return best
}

func guessWildcardFromDomain(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(parts) < 2 {
		return domain
	}
	if len(parts) == 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func asStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			text := strings.TrimSpace(asRawString(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func fileHasNonEmpty(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}

func dirHasNonEmptyExt(dir string, ext string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	wantExt := strings.ToLower(strings.TrimSpace(ext))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if wantExt != "" && !strings.HasSuffix(strings.ToLower(entry.Name()), wantExt) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Size() > 0 {
			return true
		}
	}
	return false
}

func dirHasExt(dir string, ext string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	wantExt := strings.ToLower(strings.TrimSpace(ext))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if wantExt != "" && !strings.HasSuffix(strings.ToLower(entry.Name()), wantExt) {
			continue
		}
		return true
	}
	return false
}

func globHasNonEmpty(pattern string) bool {
	if strings.TrimSpace(pattern) == "" {
		return false
	}
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return false
	}
	for _, path := range paths {
		if fileHasNonEmpty(path) {
			return true
		}
	}
	return false
}

func globHasAny(pattern string) bool {
	if strings.TrimSpace(pattern) == "" {
		return false
	}
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return false
	}
	return len(paths) > 0
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func hasDorkLinkFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			subDir := filepath.Join(dir, entry.Name())
			sub, subErr := os.ReadDir(subDir)
			if subErr != nil {
				continue
			}
			for _, f := range sub {
				if f.IsDir() {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(f.Name()))
				if strings.Contains(name, "dork") && strings.HasSuffix(name, ".txt") {
					return true
				}
			}
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name()))
		if strings.Contains(name, "dork") && strings.HasSuffix(name, ".txt") {
			return true
		}
	}
	return false
}

func asRawString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func asRawInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(v))
		return i
	default:
		return 0
	}
}
