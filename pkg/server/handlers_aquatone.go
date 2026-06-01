package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const aquatoneGalleryPreviewLimit = 400

type aquatoneJobState struct {
	Running   bool   `json:"running"`
	Status    string `json:"status"`
	LastRun   string `json:"last_run,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type aquatoneRunRequest struct {
	Type string `json:"type"`
}

type aquatoneSession struct {
	Stats aquatoneSessionStats           `json:"stats"`
	Pages map[string]aquatoneSessionPage `json:"pages"`
}

type aquatoneSessionStats struct {
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
}

type aquatoneSessionPage struct {
	URL            string   `json:"url"`
	Hostname       string   `json:"hostname"`
	Status         string   `json:"status"`
	PageTitle      string   `json:"pageTitle"`
	ScreenshotPath string   `json:"screenshotPath"`
	HasScreenshot  bool     `json:"hasScreenshot"`
	Addrs          []string `json:"addrs"`
}

type aquatoneGalleryGroup struct {
	RootDomain string               `json:"root_domain"`
	Count      int                  `json:"count"`
	Pages      []aquatoneGalleryRow `json:"pages"`
}

type aquatoneGalleryRow struct {
	URL            string   `json:"url"`
	Hostname       string   `json:"hostname"`
	Status         string   `json:"status"`
	Title          string   `json:"title"`
	ScreenshotPath string   `json:"screenshot_path"`
	IPs            []string `json:"ips,omitempty"`
}

var aquatoneSupportedTypes = map[string]bool{
	"domains":         true,
	"domains_http":    true,
	"apidomains":      true,
	"apidomains_http": true,
}

func normalizeAquatoneType(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func aquatoneOutputDir(baseDir, listType string) string {
	return filepath.Join(baseDir, "aquatone", listType)
}

func (s *Server) aquatoneRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req aquatoneRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	listType := normalizeAquatoneType(req.Type)
	if !aquatoneSupportedTypes[listType] {
		http.Error(w, "aquatone is not supported for this file type", http.StatusBadRequest)
		return
	}
	if _, err := exec.LookPath("aquatone"); err != nil {
		http.Error(w, "aquatone is not installed", http.StatusServiceUnavailable)
		return
	}
	listPath, err := s.listPath(listType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if info, statErr := os.Stat(listPath); statErr != nil || info.IsDir() {
		http.Error(w, "scope file not found", http.StatusNotFound)
		return
	}
	if count, countErr := s.cachedListLineCount(listPath); countErr != nil {
		http.Error(w, countErr.Error(), http.StatusInternalServerError)
		return
	} else if count == 0 {
		http.Error(w, "scope file has no entries", http.StatusBadRequest)
		return
	}

	s.aquatoneMu.Lock()
	job := s.aquatoneJobs[listType]
	if job == nil {
		job = &aquatoneJobState{}
		s.aquatoneJobs[listType] = job
	}
	if job.Running {
		s.aquatoneMu.Unlock()
		http.Error(w, "aquatone run already in progress", http.StatusConflict)
		return
	}
	job.Running = true
	job.Status = "queued"
	job.LastError = ""
	s.aquatoneMu.Unlock()

	go s.runAquatoneForList(listType, listPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) aquatoneStatusHandler(w http.ResponseWriter, r *http.Request) {
	listType := normalizeAquatoneType(r.URL.Query().Get("type"))
	if !aquatoneSupportedTypes[listType] {
		http.Error(w, "aquatone is not supported for this file type", http.StatusBadRequest)
		return
	}

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	outputDir := aquatoneOutputDir(baseDir, listType)
	gallery, err := loadAquatoneGallery(outputDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.aquatoneMu.Lock()
	job := s.aquatoneJobs[listType]
	resp := map[string]any{
		"running":          job != nil && job.Running,
		"status":           "idle",
		"last_run":         "",
		"last_error":       "",
		"available":        gallery.TotalScreenshots > 0,
		"group_count":      len(gallery.Groups),
		"screenshot_count": gallery.TotalScreenshots,
	}
	if job != nil {
		resp["status"] = job.Status
		resp["last_run"] = job.LastRun
		resp["last_error"] = job.LastError
	}
	s.aquatoneMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) aquatoneGalleryHandler(w http.ResponseWriter, r *http.Request) {
	listType := normalizeAquatoneType(r.URL.Query().Get("type"))
	if !aquatoneSupportedTypes[listType] {
		http.Error(w, "aquatone is not supported for this file type", http.StatusBadRequest)
		return
	}

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	outputDir := aquatoneOutputDir(baseDir, listType)
	gallery, err := loadAquatoneGallery(outputDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "no aquatone screenshots available yet", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":              listType,
		"generated_at":      gallery.GeneratedAt,
		"group_count":       len(gallery.Groups),
		"screenshot_count":  gallery.TotalScreenshots,
		"preview_limited":   gallery.PreviewLimited,
		"preview_max_items": aquatoneGalleryPreviewLimit,
		"groups":            gallery.Groups,
	})
}

func (s *Server) aquatoneAssetHandler(w http.ResponseWriter, r *http.Request) {
	listType := normalizeAquatoneType(r.URL.Query().Get("type"))
	if !aquatoneSupportedTypes[listType] {
		http.Error(w, "aquatone is not supported for this file type", http.StatusBadRequest)
		return
	}
	relPath := strings.TrimSpace(r.URL.Query().Get("path"))
	if relPath == "" {
		http.Error(w, "path query parameter required", http.StatusBadRequest)
		return
	}

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	outputDir := aquatoneOutputDir(baseDir, listType)
	cleanRel := filepath.Clean(relPath)
	if cleanRel == "." || strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
		http.Error(w, "invalid asset path", http.StatusBadRequest)
		return
	}
	fullPath := filepath.Join(outputDir, cleanRel)
	relCheck, err := filepath.Rel(outputDir, fullPath)
	if err != nil || strings.HasPrefix(relCheck, "..") {
		http.Error(w, "invalid asset path", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func (s *Server) runAquatoneForList(listType, listPath string) {
	s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
		job.Status = "running"
	})

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	parentDir := filepath.Join(baseDir, "aquatone")
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed creating output dir: %v", err), err)
		return
	}

	tmpDir, err := os.MkdirTemp(parentDir, fmt.Sprintf("%s-", listType))
	if err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed creating temp dir: %v", err), err)
		return
	}
	defer os.RemoveAll(tmpDir)

	inputFile, err := os.Open(listPath)
	if err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed opening list: %v", err), err)
		return
	}
	defer inputFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "aquatone",
		"-out", tmpDir,
		"-silent",
		"-ports", "xlarge",
		"-resolution", "1600,1200",
	)
	cmd.Stdin = inputFile
	output, err := cmd.CombinedOutput()
	logPath := filepath.Join(tmpDir, "aquatone.log")
	_ = os.WriteFile(logPath, output, 0o644)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.finishAquatoneJob(listType, "error: aquatone run timed out", ctx.Err())
			return
		}
		s.finishAquatoneJob(listType, fmt.Sprintf("error: aquatone failed (%v)", err), err)
		return
	}

	finalDir := aquatoneOutputDir(baseDir, listType)
	_ = os.RemoveAll(finalDir)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed to publish aquatone output: %v", err), err)
		return
	}

	s.finishAquatoneJob(listType, "done", nil)
}

func (s *Server) setAquatoneJobState(listType string, update func(job *aquatoneJobState)) {
	s.aquatoneMu.Lock()
	defer s.aquatoneMu.Unlock()
	job := s.aquatoneJobs[listType]
	if job == nil {
		job = &aquatoneJobState{}
		s.aquatoneJobs[listType] = job
	}
	update(job)
}

func (s *Server) finishAquatoneJob(listType, status string, err error) {
	s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
		job.Running = false
		job.Status = status
		job.LastRun = time.Now().Format(time.RFC3339)
		if err != nil {
			job.LastError = err.Error()
		} else {
			job.LastError = ""
		}
	})
}

type loadedAquatoneGallery struct {
	GeneratedAt      string
	TotalScreenshots int
	PreviewLimited   bool
	Groups           []aquatoneGalleryGroup
}

func loadAquatoneGallery(outputDir string) (loadedAquatoneGallery, error) {
	sessionPath := filepath.Join(outputDir, "aquatone_session.json")
	raw, err := os.ReadFile(sessionPath)
	if err != nil {
		return loadedAquatoneGallery{}, err
	}

	var session aquatoneSession
	if err := json.Unmarshal(raw, &session); err != nil {
		return loadedAquatoneGallery{}, err
	}

	groupMap := map[string][]aquatoneGalleryRow{}
	totalScreenshots := 0
	for _, page := range session.Pages {
		if !page.HasScreenshot || strings.TrimSpace(page.ScreenshotPath) == "" {
			continue
		}
		totalScreenshots++
		root := aquatoneRootDomain(page.Hostname)
		groupMap[root] = append(groupMap[root], aquatoneGalleryRow{
			URL:            page.URL,
			Hostname:       page.Hostname,
			Status:         page.Status,
			Title:          page.PageTitle,
			ScreenshotPath: page.ScreenshotPath,
			IPs:            page.Addrs,
		})
	}

	groupNames := make([]string, 0, len(groupMap))
	for root := range groupMap {
		groupNames = append(groupNames, root)
	}
	sort.Slice(groupNames, func(i, j int) bool {
		return strings.ToLower(groupNames[i]) < strings.ToLower(groupNames[j])
	})

	groups := make([]aquatoneGalleryGroup, 0, len(groupNames))
	rendered := 0
	previewLimited := false
	for _, root := range groupNames {
		rows := groupMap[root]
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Hostname == rows[j].Hostname {
				return rows[i].URL < rows[j].URL
			}
			return rows[i].Hostname < rows[j].Hostname
		})

		if rendered < aquatoneGalleryPreviewLimit {
			remainingSlots := aquatoneGalleryPreviewLimit - rendered
			if len(rows) > remainingSlots {
				rows = rows[:remainingSlots]
				previewLimited = true
			}
			rendered += len(rows)
			groups = append(groups, aquatoneGalleryGroup{
				RootDomain: root,
				Count:      len(groupMap[root]),
				Pages:      rows,
			})
		} else {
			previewLimited = true
		}
	}

	return loadedAquatoneGallery{
		GeneratedAt:      session.Stats.FinishedAt,
		TotalScreenshots: totalScreenshots,
		PreviewLimited:   previewLimited,
		Groups:           groups,
	}, nil
}

func aquatoneRootDomain(host string) string {
	raw := strings.TrimSpace(strings.ToLower(host))
	if raw == "" {
		return "(unknown)"
	}
	if parsedIP := net.ParseIP(raw); parsedIP != nil {
		return raw
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		raw = strings.ToLower(u.Hostname())
	}
	parts := strings.Split(raw, ".")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	if len(filtered) < 2 {
		return raw
	}
	return filtered[len(filtered)-2] + "." + filtered[len(filtered)-1]
}
