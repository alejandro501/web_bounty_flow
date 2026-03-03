package server

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

	mu          sync.Mutex
	running     bool
	status      string
	logMu       sync.Mutex
	logLines    []string
	stepMu      sync.Mutex
	steps       []app.Step
	stepState   map[string]app.StepStatus
	stepsPath   string
	configStore *configstore.Store
}

// New creates a new HTTP server wired to the bounty flow.
func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		status: "idle",
	}
	s.stepsPath = filepath.Join(cfg.Paths.LogsDir, "steps_state.json")
	s.initSteps()
	s.logger = log.New(io.MultiWriter(os.Stdout, s), "[bflow-server] ", log.LstdFlags)
	s.initConfigStore()
	appLogger := log.New(io.MultiWriter(os.Stdout, s), "[bflow] ", log.LstdFlags)
	s.app = app.New(cfg, appLogger, s, s.updateStep, s.configStore)

	s.mux.HandleFunc("/api/upload", s.corsMiddleware(s.uploadHandler))
	s.mux.HandleFunc("/api/url", s.corsMiddleware(s.urlHandler))
	s.mux.HandleFunc("/api/run", s.corsMiddleware(s.runHandler))
	s.mux.HandleFunc("/api/status", s.corsMiddleware(s.statusHandler))
	s.mux.HandleFunc("/api/logs", s.corsMiddleware(s.logsHandler))
	s.mux.HandleFunc("/api/config", s.corsMiddleware(s.configHandler))
	s.mux.HandleFunc("/api/config/providers/", s.corsMiddleware(s.providerConfigHandler))
	s.mux.HandleFunc("/api/dorking/github/run", s.corsMiddleware(s.githubRunHandler))
	s.mux.HandleFunc("/api/steps", s.corsMiddleware(s.stepsHandler))
	s.mux.HandleFunc("/api/list", s.corsMiddleware(s.listHandler))
	s.mux.HandleFunc("/api/tools", s.corsMiddleware(s.toolsHandler))
	s.mux.HandleFunc("/api/live-webservers", s.corsMiddleware(s.liveWebserversHandler))
	s.mux.HandleFunc("/api/amass-enum", s.corsMiddleware(s.amassEnumHandler))
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
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "bounty flow server is alive")
}

type uploadResponse struct {
	Status string `json:"status"`
}

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	list := r.FormValue("list_type")
	if list == "" {
		http.Error(w, "list_type is required", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	dest, err := s.listPath(list)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.saveTemporaryFile(dest, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uploadResponse{Status: "uploaded"})
}

type urlRequest struct {
	ListType string `json:"list_type"`
	URL      string `json:"url"`
}

type urlResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func (s *Server) urlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req urlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ListType == "" || req.URL == "" {
		http.Error(w, "list_type and url are required", http.StatusBadRequest)
		return
	}

	dest, err := s.listPath(req.ListType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry := strings.TrimSpace(req.URL)
	if entry == "" {
		http.Error(w, "url cannot be empty", http.StatusBadRequest)
		return
	}

	existing := readListLines(dest)
	for _, line := range existing {
		if strings.EqualFold(line, entry) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(urlResponse{
				Status:  "exists",
				Message: "Entry already exists",
			})
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, entry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(urlResponse{
		Status:  "appended",
		Message: "Entry appended",
	})
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

type toolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Required  bool   `json:"required"`
	Notes     string `json:"notes,omitempty"`
}

func (s *Server) runHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.startFlow(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := statusResponse{
		Running: s.running,
		Status:  s.status,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) stepsHandler(w http.ResponseWriter, r *http.Request) {
	// Re-evaluate artifact-based completion continuously so UI reflects
	// existing outputs even when they were produced before current process start.
	s.inferCompletedStepsFromArtifacts()

	s.stepMu.Lock()
	steps := make([]stepResponse, 0, len(s.steps))
	for _, step := range s.steps {
		status := s.stepState[step.ID]
		steps = append(steps, stepResponse{
			ID:     step.ID,
			Label:  step.Label,
			Status: status,
		})
	}
	s.stepMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]stepResponse{"steps": steps})
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	s.logMu.Lock()
	lines := append([]string(nil), s.logLines...)
	s.logMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"logs": lines})
}

func (s *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.configStore == nil {
		http.Error(w, "config store not available (BFLOW_CONFIG_KEY missing)", http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := configResponse{Version: cfg.Version, Providers: cfg.Providers}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) providerConfigHandler(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil {
		http.Error(w, "config store not available (BFLOW_CONFIG_KEY missing)", http.StatusServiceUnavailable)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/config/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}
	provider := parts[0]

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		cfg, err := s.configStore.LoadDecrypted()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := cfg.Providers[provider]
		if out == nil {
			out = &configstore.DecryptedProvider{AutoRun: true}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	case len(parts) == 2 && parts[1] == "settings" && r.Method == http.MethodPut:
		var payload settingsPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.configStore.UpdateProviderSettings(provider, payload.AutoRun); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case len(parts) >= 2 && parts[1] == "keys":
		s.handleKeys(provider, parts[2:], w, r)
		return
	default:
		http.Error(w, "unsupported config route", http.StatusNotFound)
	}
}

func (s *Server) handleKeys(provider string, rest []string, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var payload keyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := configstore.DecryptedKey{
			Label:  payload.Label,
			Value:  payload.Value,
			Active: payload.Active,
		}
		updated, err := s.configStore.UpsertKey(provider, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodPut:
		if len(rest) == 0 || rest[0] == "" {
			http.Error(w, "key id required", http.StatusBadRequest)
			return
		}
		var payload keyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := configstore.DecryptedKey{
			ID:     rest[0],
			Label:  payload.Label,
			Value:  payload.Value,
			Active: payload.Active,
		}
		updated, err := s.configStore.UpsertKey(provider, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodDelete:
		if len(rest) == 0 || rest[0] == "" {
			http.Error(w, "key id required", http.StatusBadRequest)
			return
		}
		if err := s.configStore.DeleteKey(provider, rest[0]); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) githubRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.app == nil {
		http.Error(w, "app not available", http.StatusServiceUnavailable)
		return
	}
	go func() {
		_ = s.app.RunGithubDorking(context.Background())
	}()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) listHandler(w http.ResponseWriter, r *http.Request) {
	listType := r.URL.Query().Get("type")
	if listType == "" {
		http.Error(w, "type query parameter required", http.StatusBadRequest)
		return
	}

	dest, err := s.listPath(listType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	present := false
	if info, statErr := os.Stat(dest); statErr == nil && !info.IsDir() {
		present = true
	}

	lines := readListLines(dest)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"present": present,
		"entries": lines,
	})
}

func (s *Server) liveWebserversHandler(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "live-webservers.csv")
	resp := liveWebserverResponse{Present: false, Rows: nil, Count: 0}

	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		resp.Present = true
		rows, readErr := readLiveWebserversCSV(path)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
		s.toolCheck("httprobe", false, "used as fallback when httpx fails"),
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

func (s *Server) toolCheck(name string, required bool, notes string) toolStatus {
	status := toolStatus{Name: name, Required: required, Notes: notes}
	if path, err := exec.LookPath(name); err == nil {
		status.Installed = true
		status.Path = path
	}
	return status
}

func (s *Server) recordLog(line string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	s.logLines = append(s.logLines, line)
	if len(s.logLines) > 400 {
		s.logLines = s.logLines[len(s.logLines)-400:]
	}
}

func (s *Server) Write(p []byte) (int, error) {
	lines := strings.Split(string(p), "\n")
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			continue
		}
		s.recordLog(strings.TrimRight(line, "\r"))
	}
	return len(p), nil
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
	s.stepMu.Lock()
	for _, step := range s.steps {
		s.stepState[step.ID] = app.StepPending
	}
	s.stepMu.Unlock()
	s.persistStepState()
}

func (s *Server) updateStep(id string, status app.StepStatus) {
	s.stepMu.Lock()
	if _, ok := s.stepState[id]; ok {
		s.stepState[id] = status
	}
	s.stepMu.Unlock()
	s.persistStepState()
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
	doneIfPending("amass", dirHasNonEmptyExt(amassDir, ".txt"))
	doneIfPending("sublist3r",
		dirHasNonEmptyExt(filepath.Join(rawDir, "sublist3r"), ".txt") ||
			globHasNonEmpty(filepath.Join(reconDir, "sublist3r_*.txt")),
	)
	doneIfPending("assetfinder",
		dirHasNonEmptyExt(filepath.Join(rawDir, "assetfinder"), ".txt") ||
			globHasNonEmpty(filepath.Join(reconDir, "assetfinder_*.txt")),
	)
	doneIfPending("gau",
		dirHasNonEmptyExt(filepath.Join(rawDir, "gau"), ".txt") ||
			globHasNonEmpty(filepath.Join(reconDir, "gau_*.txt")),
	)
	doneIfPending("ctl",
		dirHasNonEmptyExt(filepath.Join(rawDir, "ctl"), ".json") ||
			globHasNonEmpty(filepath.Join(reconDir, "ctl_*.json")),
	)
	doneIfPending("subfinder",
		dirHasNonEmptyExt(filepath.Join(rawDir, "subfinder"), ".txt") ||
			globHasNonEmpty(filepath.Join(reconDir, "subfinder_*.txt")),
	)
	doneIfPending("dnsx-validate",
		fileHasNonEmpty(filepath.Join(rawDir, "dnsx-validate", "validated_hosts.txt")) ||
			fileHasNonEmpty(filepath.Join(reconDir, "dnsx_validated_hosts.txt")),
	)
	doneIfPending("consolidate", fileHasNonEmpty(s.cfg.Lists.Domains))
	doneIfPending("httpx", fileHasNonEmpty(filepath.Join(baseDir, "live-webservers.csv")))
	doneIfPending("robots-sitemaps", fileHasNonEmpty(filepath.Join(s.cfg.Paths.RobotsDir, "_hits.txt")) || fileHasNonEmpty(s.cfg.Paths.SitemapsFile))
	doneIfPending("waybackurls",
		fileExists(filepath.Join(reconDir, "waybackurls_urls.txt")) ||
			fileExists(filepath.Join(reconDir, "urls_waybackurls.txt")),
	)
	doneIfPending("katana",
		fileExists(filepath.Join(reconDir, "katana_urls.txt")) ||
			fileExists(filepath.Join(reconDir, "urls_katana.txt")),
	)
	doneIfPending("url-corpus",
		fileHasNonEmpty(filepath.Join(reconDir, "all_urls.txt")) ||
			fileHasNonEmpty(filepath.Join(reconDir, "urls_all.txt")),
	)
	doneIfPending("param-fuzz", fileExists(filepath.Join(baseDir, "fuzzing", "params", "summary.csv")))
	doneIfPending("injection-checks", fileExists(filepath.Join(baseDir, "fuzzing", "injection", "summary.csv")))
	doneIfPending("server-input-checks", fileExists(filepath.Join(baseDir, "fuzzing", "server-input", "summary.csv")))
	doneIfPending("adv-injection-checks", fileExists(filepath.Join(baseDir, "fuzzing", "adv-injection", "summary.csv")))
	doneIfPending("dork-links", hasDorkLinkFiles(s.cfg.Paths.DorkingDir))
	doneIfPending("cewl",
		fileHasNonEmpty(filepath.Join(reconDir, "cewl_custom_wordlist.txt")) ||
			fileHasNonEmpty(filepath.Join(baseDir, "cewl_custom_wordlist.txt")),
	)
	doneIfPending("fuzz-docs", fileExists(filepath.Join(baseDir, "fuzzing", "documentation", "doc_hits.txt")))
	doneIfPending("fuzz-dirs", fileExists(filepath.Join(baseDir, "fuzzing", "ffuf", "dir_hits.txt")))
	s.persistStepState()
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
	s.running = true
	s.status = "running"
	s.resetSteps()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.status = fmt.Sprintf("last run finished at %s", time.Now().Format(time.RFC3339))
			s.mu.Unlock()
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := s.app.Run(ctx); err != nil {
			s.logger.Printf("flow run failed: %v", err)
			s.mu.Lock()
			s.status = fmt.Sprintf("error: %v", err)
			s.mu.Unlock()
		}
	}()

	return nil
}

func (s *Server) missingRequiredToolsForRun() []string {
	// Subdomain discovery pipeline only runs when wildcards are provided.
	if len(readListLines(s.cfg.Lists.Wildcards)) == 0 {
		return nil
	}

	required := []string{"amass", "assetfinder", "gau", "subfinder", "httpx"}
	var missing []string
	for _, name := range required {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
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
	case "apidomains":
		return s.cfg.Lists.APIDomains, nil
	case "out_of_scope":
		return s.cfg.Lists.OutOfScope, nil
	case "live_webservers_csv":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "live-webservers.csv"), nil
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
	case "param_fuzz_summary":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "params", "summary.csv"), nil
	case "injection_sqli_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "sqli_hits.jsonl"), nil
	case "injection_nosqli_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "nosqli_hits.jsonl"), nil
	case "injection_xpath_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "xpath_hits.jsonl"), nil
	case "injection_ldap_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "ldap_hits.jsonl"), nil
	case "injection_summary":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "injection", "summary.csv"), nil
	case "server_input_os_command_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "os_command_hits.jsonl"), nil
	case "server_input_path_traversal_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "path_traversal_hits.jsonl"), nil
	case "server_input_file_inclusion_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "file_inclusion_hits.jsonl"), nil
	case "server_input_summary":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "server-input", "summary.csv"), nil
	case "adv_injection_xxe_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "xxe_hits.jsonl"), nil
	case "adv_injection_soap_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "soap_hits.jsonl"), nil
	case "adv_injection_ssrf_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "ssrf_hits.jsonl"), nil
	case "adv_injection_smtp_hits":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "smtp_hits.jsonl"), nil
	case "adv_injection_summary":
		return filepath.Join(filepath.Dir(s.cfg.Lists.Domains), "fuzzing", "adv-injection", "summary.csv"), nil
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

func readLiveWebserversCSV(path string) ([]liveWebserverRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) <= 1 {
		return nil, nil
	}

	var out []liveWebserverRow
	for i := 1; i < len(records); i++ {
		rec := records[i]
		if len(rec) < 6 {
			continue
		}
		statusCode, _ := strconv.Atoi(strings.TrimSpace(rec[1]))
		contentLength, _ := strconv.Atoi(strings.TrimSpace(rec[5]))
		tech := strings.TrimSpace(rec[4])
		var techs []string
		if tech != "" {
			for _, t := range strings.Split(tech, ";") {
				t = strings.TrimSpace(t)
				if t != "" {
					techs = append(techs, t)
				}
			}
		}
		out = append(out, liveWebserverRow{
			URL:           strings.TrimSpace(rec[0]),
			StatusCode:    statusCode,
			Title:         strings.TrimSpace(rec[2]),
			WebServer:     strings.TrimSpace(rec[3]),
			Technologies:  techs,
			ContentLength: contentLength,
		})
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
	hostIPs := readDNSXHostIPs(filepath.Join(filepath.Dir(dir), "raw", "dnsx-validate", "results.txt"))

	var rows []amassEnumRow
	seen := make(map[string]struct{})
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
		for _, host := range readListLines(path) {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			ips := hostIPs[strings.ToLower(host)]
			if len(ips) == 0 {
				key := strings.ToLower(host) + "|" + strings.ToLower(seed) + "|"
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				rows = append(rows, amassEnumRow{
					Name:   host,
					Domain: seed,
					Source: "amass",
				})
				continue
			}
			for _, ip := range ips {
				key := strings.ToLower(host) + "|" + strings.ToLower(seed) + "|" + ip
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				rows = append(rows, amassEnumRow{
					Name:   host,
					Domain: seed,
					IP:     ip,
					Source: "amass",
				})
			}
		}
	}

	return rows, nil
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
