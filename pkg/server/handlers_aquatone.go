package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
const aquatoneScreenshotRetryLimit = 3

var (
	errAquatoneAlreadyRunning = errors.New("aquatone run already in progress")
	errAquatoneNotInstalled   = errors.New("aquatone is not installed")
)

type aquatoneJobState struct {
	Running   bool               `json:"running"`
	Status    string             `json:"status"`
	LastRun   string             `json:"last_run,omitempty"`
	LastError string             `json:"last_error,omitempty"`
	LogPath   string             `json:"log_path,omitempty"`
	Cancel    context.CancelFunc `json:"-"`
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
	HeadersPath    string   `json:"headersPath"`
	BodyPath       string   `json:"bodyPath"`
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
	"robots_urls":     true,
	"wayback_urls":    true,
	"katana_urls":     true,
	"all_urls":        true,
}

func normalizeAquatoneType(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func aquatoneOutputDir(baseDir, listType string) string {
	return filepath.Join(baseDir, "aquatone", listType)
}

func aquatoneFailedRunDir(baseDir, listType string) string {
	return filepath.Join(baseDir, "aquatone", listType+"_failed")
}

func (s *Server) startAquatoneJob(listType string) (string, error) {
	if !aquatoneSupportedTypes[listType] {
		return "", errors.New("aquatone is not supported for this file type")
	}
	if _, err := exec.LookPath("aquatone"); err != nil {
		return "", errAquatoneNotInstalled
	}
	listPath, err := s.listPath(listType)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(listPath); statErr != nil {
		return "", os.ErrNotExist
	} else if info.IsDir() {
		return "", errors.New("scope file not found")
	}
	if count, countErr := s.cachedListLineCount(listPath); countErr != nil {
		return "", countErr
	} else if count == 0 {
		return "", errors.New("scope file has no entries")
	}

	s.aquatoneMu.Lock()
	job := s.aquatoneJobs[listType]
	if job == nil {
		job = &aquatoneJobState{}
		s.aquatoneJobs[listType] = job
	}
	if job.Running {
		s.aquatoneMu.Unlock()
		return "", errAquatoneAlreadyRunning
	}
	job.Running = true
	job.Status = "queued"
	job.LastError = ""
	s.aquatoneMu.Unlock()

	go s.runAquatoneForList(listType, listPath)

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	return aquatoneOutputDir(baseDir, listType), nil
}

func (s *Server) startAquatoneForHTTPDomains(ctx context.Context, path string) {
	if ctx.Err() != nil {
		return
	}
	outputDir, err := s.startAquatoneJob("domains_http")
	if err != nil {
		if errors.Is(err, errAquatoneAlreadyRunning) {
			s.logger.Printf("aquatone auto-start skipped for HTTP Domains: already running")
			return
		}
		s.logger.Printf("aquatone auto-start skipped for HTTP Domains: %v", err)
		return
	}
	s.logger.Printf("aquatone auto-started for HTTP Domains from %s; output: %s", path, outputDir)
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
	outputDir, err := s.startAquatoneJob(listType)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errAquatoneNotInstalled) {
			status = http.StatusServiceUnavailable
		} else if errors.Is(err, errAquatoneAlreadyRunning) {
			status = http.StatusConflict
		} else if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":     "started",
		"output_dir": outputDir,
	})
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
		"output_dir":       outputDir,
		"failed_log":       filepath.Join(aquatoneFailedRunDir(baseDir, listType), "aquatone.log"),
		"available":        gallery.TotalScreenshots > 0,
		"group_count":      len(gallery.Groups),
		"screenshot_count": gallery.TotalScreenshots,
	}
	if job != nil {
		resp["status"] = job.Status
		resp["last_run"] = job.LastRun
		resp["last_error"] = job.LastError
		resp["can_stop"] = job.Running && job.Cancel != nil
	}
	s.aquatoneMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) aquatoneStopHandler(w http.ResponseWriter, r *http.Request) {
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

	s.aquatoneMu.Lock()
	job := s.aquatoneJobs[listType]
	if job == nil || !job.Running || job.Cancel == nil {
		s.aquatoneMu.Unlock()
		http.Error(w, "no aquatone run in progress", http.StatusConflict)
		return
	}
	cancel := job.Cancel
	job.Status = "stopping"
	s.aquatoneMu.Unlock()

	cancel()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopping"})
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

func (s *Server) aquatoneLogHandler(w http.ResponseWriter, r *http.Request) {
	listType := normalizeAquatoneType(r.URL.Query().Get("type"))
	if !aquatoneSupportedTypes[listType] {
		http.Error(w, "aquatone is not supported for this file type", http.StatusBadRequest)
		return
	}

	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	s.aquatoneMu.Lock()
	job := s.aquatoneJobs[listType]
	logPath := ""
	if job != nil {
		logPath = strings.TrimSpace(job.LogPath)
	}
	s.aquatoneMu.Unlock()

	candidates := []string{}
	if logPath != "" {
		candidates = append(candidates, logPath)
	}
	candidates = append(candidates,
		filepath.Join(aquatoneOutputDir(baseDir, listType), "aquatone.log"),
		filepath.Join(aquatoneFailedRunDir(baseDir, listType), "aquatone.log"),
	)

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		data, err := readFileTail(candidate, 200_000)
		if err == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		if !errors.Is(err, os.ErrNotExist) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte{})
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
	s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
		job.Cancel = cancel
	})

	logPath := filepath.Join(tmpDir, "aquatone.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed creating aquatone log: %v", err), err)
		return
	}
	defer logFile.Close()
	s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
		job.LogPath = logPath
	})

	args := []string{
		"-out", tmpDir,
		"-silent",
		"-ports", "xlarge",
		"-resolution", "1600,1200",
	}
	if chromePath := aquatoneChromePath(); chromePath != "" {
		args = append(args, "-chrome-path", chromePath)
	}
	cmd := exec.CommandContext(ctx, "aquatone", args...)
	cmd.Stdin = inputFile
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err = cmd.Run()
	if err != nil {
		failedDir := aquatoneFailedRunDir(baseDir, listType)
		_ = os.RemoveAll(failedDir)
		_ = os.Rename(tmpDir, failedDir)
		s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
			job.LogPath = filepath.Join(failedDir, "aquatone.log")
		})
		if ctx.Err() == context.DeadlineExceeded {
			s.finishAquatoneJob(listType, "error: aquatone run timed out", ctx.Err())
			return
		}
		if ctx.Err() == context.Canceled {
			s.finishAquatoneJob(listType, "stopped", nil)
			return
		}
		s.finishAquatoneJob(listType, fmt.Sprintf("error: aquatone failed (%v)", err), err)
		return
	}

	if err := s.retryMissingAquatoneScreenshots(ctx, listType, tmpDir, args, logFile); err != nil {
		failedDir := aquatoneFailedRunDir(baseDir, listType)
		_ = os.RemoveAll(failedDir)
		_ = os.Rename(tmpDir, failedDir)
		s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
			job.LogPath = filepath.Join(failedDir, "aquatone.log")
		})
		if ctx.Err() == context.DeadlineExceeded {
			s.finishAquatoneJob(listType, "error: aquatone run timed out", ctx.Err())
			return
		}
		if ctx.Err() == context.Canceled {
			s.finishAquatoneJob(listType, "stopped", nil)
			return
		}
		s.finishAquatoneJob(listType, fmt.Sprintf("error: aquatone retry failed (%v)", err), err)
		return
	}

	finalDir := aquatoneOutputDir(baseDir, listType)
	_ = os.RemoveAll(finalDir)
	if err := os.Rename(tmpDir, finalDir); err != nil {
		s.finishAquatoneJob(listType, fmt.Sprintf("error: failed to publish aquatone output: %v", err), err)
		return
	}
	s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
		job.LogPath = filepath.Join(finalDir, "aquatone.log")
	})

	s.finishAquatoneJob(listType, "done", nil)
}

func (s *Server) retryMissingAquatoneScreenshots(ctx context.Context, listType, outputDir string, baseArgs []string, logFile *os.File) error {
	mergedAny := false
	for attempt := 1; attempt <= aquatoneScreenshotRetryLimit; attempt++ {
		missingURLs, err := aquatoneMissingScreenshotURLs(outputDir)
		if err != nil {
			return err
		}
		if len(missingURLs) == 0 {
			if attempt == 1 {
				_, _ = logFile.WriteString("\n[bflow] Aquatone captured screenshots for all discovered pages.\n")
			} else {
				_, _ = logFile.WriteString("\n[bflow] Aquatone retry captured all remaining screenshots.\n")
			}
			return nil
		}

		s.setAquatoneJobState(listType, func(job *aquatoneJobState) {
			job.Status = fmt.Sprintf("retrying missing screenshots (%d/%d)", attempt, aquatoneScreenshotRetryLimit)
		})
		_, _ = logFile.WriteString(fmt.Sprintf("\n[bflow] Aquatone retry %d/%d for %d missing screenshots.\n", attempt, aquatoneScreenshotRetryLimit, len(missingURLs)))

		retryDir, err := os.MkdirTemp(filepath.Dir(outputDir), fmt.Sprintf("%s-retry-%d-", filepath.Base(outputDir), attempt))
		if err != nil {
			return err
		}

		retryArgs := replaceAquatoneOutArg(baseArgs, retryDir)
		cmd := exec.CommandContext(ctx, "aquatone", retryArgs...)
		cmd.Stdin = strings.NewReader(strings.Join(missingURLs, "\n") + "\n")
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		runErr := cmd.Run()
		if ctx.Err() != nil {
			_ = os.RemoveAll(retryDir)
			return ctx.Err()
		}
		if runErr != nil {
			_, _ = logFile.WriteString(fmt.Sprintf("[bflow] Aquatone retry %d failed: %v\n", attempt, runErr))
			_ = os.RemoveAll(retryDir)
			continue
		}

		merged, err := mergeAquatoneRetryOutput(outputDir, retryDir)
		_ = os.RemoveAll(retryDir)
		if err != nil {
			return err
		}
		_, _ = logFile.WriteString(fmt.Sprintf("[bflow] Aquatone retry %d recovered %d screenshots.\n", attempt, merged))
		if merged > 0 {
			mergedAny = true
		}
	}

	missingURLs, err := aquatoneMissingScreenshotURLs(outputDir)
	if err != nil {
		return err
	}
	if len(missingURLs) > 0 {
		_, _ = logFile.WriteString(fmt.Sprintf("\n[bflow] Aquatone left %d screenshots missing after %d retries.\n", len(missingURLs), aquatoneScreenshotRetryLimit))
	}

	if mergedAny {
		_, _ = logFile.WriteString("\n[bflow] Regenerating Aquatone report after retries.\n")
		cmd := exec.CommandContext(ctx, "aquatone", "-session", filepath.Join(outputDir, "aquatone_session.json"), "-out", outputDir)
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		return cmd.Run()
	}
	return nil
}

func replaceAquatoneOutArg(args []string, outputDir string) []string {
	replaced := append([]string(nil), args...)
	for i := 0; i < len(replaced)-1; i++ {
		if replaced[i] == "-out" {
			replaced[i+1] = outputDir
			return replaced
		}
	}
	return append(replaced, "-out", outputDir)
}

func aquatoneMissingScreenshotURLs(outputDir string) ([]string, error) {
	session, err := readAquatoneSession(filepath.Join(outputDir, "aquatone_session.json"))
	if err != nil {
		return nil, err
	}
	missing := make([]string, 0)
	for _, page := range session.Pages {
		if strings.TrimSpace(page.URL) == "" {
			continue
		}
		if !page.HasScreenshot || strings.TrimSpace(page.ScreenshotPath) == "" {
			missing = append(missing, page.URL)
			continue
		}
		if _, err := os.Stat(filepath.Join(outputDir, filepath.Clean(page.ScreenshotPath))); err != nil {
			missing = append(missing, page.URL)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func mergeAquatoneRetryOutput(outputDir, retryDir string) (int, error) {
	mainSessionPath := filepath.Join(outputDir, "aquatone_session.json")
	mainSession, err := readAquatoneSession(mainSessionPath)
	if err != nil {
		return 0, err
	}
	retrySession, err := readAquatoneSession(filepath.Join(retryDir, "aquatone_session.json"))
	if err != nil {
		return 0, err
	}

	mainKeysByURL := map[string]string{}
	for key, page := range mainSession.Pages {
		mainKeysByURL[page.URL] = key
	}

	merged := 0
	for retryKey, retryPage := range retrySession.Pages {
		if !retryPage.HasScreenshot || strings.TrimSpace(retryPage.ScreenshotPath) == "" {
			continue
		}
		if err := copyAquatonePageArtifacts(outputDir, retryDir, retryPage); err != nil {
			return merged, err
		}
		if mainKey, ok := mainKeysByURL[retryPage.URL]; ok {
			mainSession.Pages[mainKey] = retryPage
		} else {
			mainSession.Pages[retryKey] = retryPage
		}
		merged++
	}

	raw, err := json.MarshalIndent(mainSession, "", "  ")
	if err != nil {
		return merged, err
	}
	return merged, os.WriteFile(mainSessionPath, append(raw, '\n'), 0o644)
}

func copyAquatonePageArtifacts(outputDir, retryDir string, page aquatoneSessionPage) error {
	for _, relPath := range []string{page.HeadersPath, page.BodyPath, page.ScreenshotPath} {
		relPath = strings.TrimSpace(relPath)
		if relPath == "" {
			continue
		}
		if err := copyAquatoneArtifact(outputDir, retryDir, relPath); err != nil {
			return err
		}
	}
	return nil
}

func copyAquatoneArtifact(outputDir, retryDir, relPath string) error {
	cleanRel := filepath.Clean(relPath)
	if cleanRel == "." || strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
		return fmt.Errorf("invalid aquatone artifact path: %s", relPath)
	}
	src := filepath.Join(retryDir, cleanRel)
	dst := filepath.Join(outputDir, cleanRel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func readAquatoneSession(path string) (aquatoneSession, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return aquatoneSession{}, err
	}
	var session aquatoneSession
	if err := json.Unmarshal(raw, &session); err != nil {
		return aquatoneSession{}, err
	}
	if session.Pages == nil {
		session.Pages = map[string]aquatoneSessionPage{}
	}
	return session, nil
}

func readFileTail(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	offset := int64(0)
	if maxBytes > 0 && info.Size() > maxBytes {
		offset = info.Size() - maxBytes
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		return append([]byte("[showing last log lines]\n"), data...), nil
	}
	return data, nil
}

func aquatoneChromePath() string {
	for _, path := range []string{
		os.Getenv("AQUATONE_CHROME_PATH"),
		"/usr/local/bin/chromium-aquatone",
		"/usr/bin/chromium-browser",
		"/usr/bin/chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
	} {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
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
		job.Cancel = nil
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
