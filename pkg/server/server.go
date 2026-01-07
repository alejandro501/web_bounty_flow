package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rojo/hack/web_bounty_flow/pkg/app"
	"github.com/rojo/hack/web_bounty_flow/pkg/config"
)

// Server provides the HTTP layer for interacting with the bounty flow.
type Server struct {
	cfg    *config.Config
	app    *app.App
	logger *log.Logger
	mux    *http.ServeMux

	mu       sync.Mutex
	running  bool
	status   string
	logMu    sync.Mutex
	logLines []string
	stepMu    sync.Mutex
	steps     []app.Step
	stepState map[string]app.StepStatus
}

// New creates a new HTTP server wired to the bounty flow.
func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		status: "idle",
	}
	s.initSteps()
	s.logger = log.New(io.MultiWriter(os.Stdout, s), "[bflow-server] ", log.LstdFlags)
	appLogger := log.New(io.MultiWriter(os.Stdout, s), "[bflow] ", log.LstdFlags)
	s.app = app.New(cfg, appLogger, s, s.updateStep)

	s.mux.HandleFunc("/api/upload", s.corsMiddleware(s.uploadHandler))
	s.mux.HandleFunc("/api/url", s.corsMiddleware(s.urlHandler))
	s.mux.HandleFunc("/api/run", s.corsMiddleware(s.runHandler))
	s.mux.HandleFunc("/api/status", s.corsMiddleware(s.statusHandler))
	s.mux.HandleFunc("/api/logs", s.corsMiddleware(s.logsHandler))
	s.mux.HandleFunc("/api/steps", s.corsMiddleware(s.stepsHandler))
	s.mux.HandleFunc("/api/list", s.corsMiddleware(s.listHandler))
	s.mux.HandleFunc("/", s.corsMiddleware(s.rootHandler))

	return s
}

type stepResponse struct {
	ID     string         `json:"id"`
	Label  string         `json:"label"`
	Status app.StepStatus `json:"status"`
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

type runRequest struct {
	Organization string `json:"organization"`
	OrgList      string `json:"org_list"`
}

type statusResponse struct {
	Running bool   `json:"running"`
	Status  string `json:"status"`
}

func (s *Server) runHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req runRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := s.startFlow(req.Organization, req.OrgList); err != nil {
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

	lines := readListLines(dest)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"entries": lines})
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
}

func (s *Server) resetSteps() {
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
}

func (s *Server) startFlow(org, orgList string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("flow already running")
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

		opts := app.Options{
			Organization: org,
			OrgList:      orgList,
		}

		if err := s.app.Run(ctx, opts); err != nil {
			s.logger.Printf("flow run failed: %v", err)
			s.mu.Lock()
			s.status = fmt.Sprintf("error: %v", err)
			s.mu.Unlock()
		}
	}()

	return nil
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
