package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rojo/hack/web_bounty_flow/pkg/config"
	"github.com/rojo/hack/web_bounty_flow/pkg/configstore"
	"github.com/rojo/hack/web_bounty_flow/pkg/dorking"
)

// StepStatus tracks a flow step state.
type StepStatus string

const (
	StepPending StepStatus = "pending"
	StepRunning StepStatus = "running"
	StepDone    StepStatus = "done"
	StepSkipped StepStatus = "skipped"
	StepError   StepStatus = "error"
)

// Step describes a flow stage for UI progress.
type Step struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

const (
	StepLoadConfig     = "load-config"
	StepValidateInputs = "validate-inputs"
	StepAmass          = "amass"
	StepSublist3r      = "sublist3r"
	StepAssetfinder    = "assetfinder"
	StepGAU            = "gau"
	StepCTL            = "ctl"
	StepSubfinder      = "subfinder"
	StepConsolidate    = "consolidate"
	StepHTTPX          = "httpx"
	StepCeWL           = "cewl"
	StepGithubDork     = "github-dork"
)

var flowSteps = []Step{
	{ID: StepLoadConfig, Label: "Load flow.yaml and initialize recon runtime."},
	{ID: StepValidateInputs, Label: "Validate scope readiness (at least one non-empty input list is required)."},
	{ID: StepAmass, Label: "Run amass enum for each wildcard."},
	{ID: StepSublist3r, Label: "Run sublist3r in parallel with other passive tools."},
	{ID: StepAssetfinder, Label: "Run assetfinder in parallel with other passive tools."},
	{ID: StepGAU, Label: "Run gau in parallel with other passive tools."},
	{ID: StepCTL, Label: "Query certificate transparency logs in parallel."},
	{ID: StepSubfinder, Label: "Run subfinder in parallel with other passive tools."},
	{ID: StepConsolidate, Label: "Consolidate all discovered hosts and remove duplicates."},
	{ID: StepHTTPX, Label: "Probe consolidated hosts with httpx for live web servers."},
	{ID: StepCeWL, Label: "Generate custom CeWL wordlist from live web servers."},
}

// FlowSteps returns the ordered flow steps for UI rendering.
func FlowSteps() []Step {
	out := make([]Step, len(flowSteps))
	copy(out, flowSteps)
	return out
}

// App coordinates each stage of the bounty flow.
type App struct {
	cfg             *config.Config
	logger          *log.Logger
	httpClient      *http.Client
	httpDomainsPath string
	logWriter       io.Writer
	stepUpdate      func(id string, status StepStatus)
	configStore     *configstore.Store
}

// New creates an orchestrator with the provided configuration.
func New(cfg *config.Config, logger *log.Logger, logWriter io.Writer, stepUpdate func(id string, status StepStatus), configStore *configstore.Store) *App {
	return &App{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logWriter:   logWriter,
		stepUpdate:  stepUpdate,
		configStore: configStore,
	}
}

// Run executes the recon flow.
func (a *App) Run(ctx context.Context) error {
	a.updateStep(StepLoadConfig, StepRunning)
	a.updateStep(StepLoadConfig, StepDone)

	a.logger.Println("preparing directories")
	if err := a.prepareDirectories(); err != nil {
		return err
	}
	if err := a.normalizeLegacyListFiles(); err != nil {
		return err
	}

	if err := a.runStep(StepValidateInputs, func() error {
		return a.validateReconInputs()
	}); err != nil {
		return err
	}

	a.logger.Println("running wildcard recon pipeline")
	if err := a.passiveRecon(ctx); err != nil {
		return err
	}

	return nil
}

// RunGithubDorking triggers the GitHub dorking step without running the full flow.
func (a *App) RunGithubDorking(ctx context.Context) error {
	return a.githubDorking(ctx)
}

func (a *App) updateStep(id string, status StepStatus) {
	if a.stepUpdate == nil {
		return
	}
	a.stepUpdate(id, status)
}

func (a *App) runStep(id string, fn func() error) error {
	a.updateStep(id, StepRunning)
	if err := fn(); err != nil {
		a.updateStep(id, StepError)
		return err
	}
	a.updateStep(id, StepDone)
	return nil
}

func (a *App) skipStep(id string) {
	a.updateStep(id, StepSkipped)
}

func (a *App) githubDorking(ctx context.Context) error {
	if a.configStore == nil {
		a.skipStep(StepGithubDork)
		return nil
	}

	cfg, err := a.configStore.LoadDecrypted()
	if err != nil {
		return err
	}

	gh := cfg.Providers["github"]
	if gh == nil || !gh.AutoRun {
		a.skipStep(StepGithubDork)
		return nil
	}

	activeKeys := gh.ActiveTokens()
	if len(activeKeys) == 0 {
		a.skipStep(StepGithubDork)
		return nil
	}

	var tokens []dorking.Token
	for _, key := range activeKeys {
		tokens = append(tokens, dorking.Token{ID: key.ID, Value: key.Value})
	}

	outputDir := filepath.Join(a.cfg.Paths.DorkingDir, "github")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	opts := dorking.GithubOptions{
		OutputDir: outputDir,
		Tokens:    tokens,
		Logger:    a.logger,
		UpdateToken: func(tokenID string, used time.Time, lastErr string) {
			_ = a.configStore.UpdateTokenUsage("github", tokenID, used, lastErr)
		},
	}

	return dorking.RunGithubSearch(ctx, opts)
}

func (a *App) prepareDirectories() error {
	directories := []string{
		a.cfg.Paths.RobotsDir,
		filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsHitsDir),
		filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsNoHitsDir),
		a.cfg.Paths.DorkingDir,
		filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir),
		filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir, a.cfg.Paths.FuzzingHitsDir),
		filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir, a.cfg.Paths.FuzzingNoHitsDir),
		filepath.Join(a.cfg.Paths.FuzzingDir, "documentation"),
		a.cfg.Paths.LogsDir,
		a.cfg.Paths.NmapDir,
	}

	listFiles := []string{
		a.cfg.Lists.Organizations,
		a.cfg.Lists.IPs,
		a.cfg.Lists.Wildcards,
		a.cfg.Lists.Domains,
		a.cfg.Lists.APIDomains,
		a.cfg.Lists.OutOfScope,
	}

	for _, listPath := range listFiles {
		if listPath == "" {
			continue
		}
		dir := filepath.Dir(listPath)
		if dir == "." || dir == "" {
			continue
		}
		directories = append(directories, dir)
	}

	for _, dir := range directories {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) passiveRecon(ctx context.Context) error {
	for _, step := range []string{
		StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepConsolidate, StepHTTPX, StepCeWL,
	} {
		a.updateStep(step, StepPending)
	}

	if !fileExists(a.cfg.Lists.Wildcards) || len(readSafeLines(a.cfg.Lists.Wildcards)) == 0 {
		for _, step := range []string{
			StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepConsolidate, StepHTTPX, StepCeWL,
		} {
			a.skipStep(step)
		}
		return nil
	}

	return a.runSubdomainDiscovery(ctx)
}

func (a *App) validateReconInputs() error {
	scopeInputs := []struct {
		label string
		path  string
	}{
		{label: "organizations", path: a.cfg.Lists.Organizations},
		{label: "wildcards", path: a.cfg.Lists.Wildcards},
		{label: "domains", path: a.cfg.Lists.Domains},
		{label: "apidomains", path: a.cfg.Lists.APIDomains},
		{label: "ips", path: a.cfg.Lists.IPs},
	}

	var available []string

	for _, item := range scopeInputs {
		if fileExists(item.path) && len(readSafeLines(item.path)) > 0 {
			available = append(available, fmt.Sprintf("%s (%s)", item.label, item.path))
		}
	}

	if len(available) == 0 {
		return fmt.Errorf("required recon input files are not ready; provide at least one non-empty scope file: organizations, wildcards, domains, apidomains, or ips")
	}

	a.logger.Printf("scope inputs available: %s", strings.Join(available, ", "))
	return nil
}

func (a *App) normalizeLegacyListFiles() error {
	paths := []string{
		a.cfg.Lists.Organizations,
		a.cfg.Lists.IPs,
		a.cfg.Lists.Wildcards,
		a.cfg.Lists.Domains,
		a.cfg.Lists.APIDomains,
		a.cfg.Lists.OutOfScope,
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		legacy := path + ".txt"

		switch {
		case !fileExists(path) && fileExists(legacy):
			a.logger.Printf("migrating legacy list file %s -> %s", legacy, path)
			if err := os.Rename(legacy, path); err != nil {
				return err
			}
		case fileExists(path) && fileExists(legacy):
			primary := readSafeLines(path)
			old := readSafeLines(legacy)
			merged := unique(append(primary, old...))
			if err := os.WriteFile(path, []byte(strings.Join(merged, "\n")), 0o644); err != nil {
				return err
			}
			if err := os.Remove(legacy); err != nil {
				return err
			}
			a.logger.Printf("merged legacy list file %s into %s", legacy, path)
		}
	}

	return nil
}

func (a *App) runSubdomainDiscovery(ctx context.Context) error {
	seeds, err := readFileLines(a.cfg.Lists.Wildcards)
	if err != nil {
		return err
	}

	seenSeeds := make(map[string]struct{})
	var normalizedSeeds []string
	for _, seed := range seeds {
		normalized := normalizeSubdomainSeed(seed)
		if normalized == "" {
			continue
		}
		if _, ok := seenSeeds[normalized]; ok {
			continue
		}
		seenSeeds[normalized] = struct{}{}
		normalizedSeeds = append(normalizedSeeds, normalized)
	}
	if len(normalizedSeeds) == 0 {
		return fmt.Errorf("no valid wildcard seeds in %s", a.cfg.Lists.Wildcards)
	}

	toolResults := map[string]map[string]struct{}{
		StepAmass:       {},
		StepSublist3r:   {},
		StepAssetfinder: {},
		StepGAU:         {},
		StepCTL:         {},
		StepSubfinder:   {},
	}
	var resultMu sync.Mutex
	appendResults := func(step string, hosts []string) {
		resultMu.Lock()
		defer resultMu.Unlock()
		for _, host := range hosts {
			host = normalizeDorkTarget(host)
			if host == "" {
				continue
			}
			toolResults[step][host] = struct{}{}
		}
	}

	if err := a.runStep(StepAmass, func() error {
		for _, seed := range normalizedSeeds {
			stdout, err := a.runCommandCapture(ctx, "amass", "enum", "-passive", "-d", seed, "-silent")
			if err != nil {
				return fmt.Errorf("amass failed for %s: %w", seed, err)
			}
			appendResults(StepAmass, parseDomainLines(stdout, seed))
		}
		return nil
	}); err != nil {
		return err
	}

	type toolRunner struct {
		step       string
		required   string
		runForSeed func(seed string) ([]string, error)
	}

	runners := []toolRunner{
		{
			step:     StepSublist3r,
			required: "sublist3r",
			runForSeed: func(seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "sublist3r", "-d", seed, "-o", "/dev/stdout")
				if err != nil {
					return nil, err
				}
				return parseDomainLines(stdout, seed), nil
			},
		},
		{
			step:     StepAssetfinder,
			required: "assetfinder",
			runForSeed: func(seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "assetfinder", "--subs-only", seed)
				if err != nil {
					return nil, err
				}
				return parseDomainLines(stdout, seed), nil
			},
		},
		{
			step:     StepGAU,
			required: "gau",
			runForSeed: func(seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "gau", "--subs", seed)
				if err != nil {
					return nil, err
				}
				return parseHostsFromURLs(stdout, seed), nil
			},
		},
		{
			step:     StepCTL,
			required: "",
			runForSeed: func(seed string) ([]string, error) {
				return a.fetchCTLHosts(ctx, seed)
			},
		},
		{
			step:     StepSubfinder,
			required: "subfinder",
			runForSeed: func(seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "subfinder", "-silent", "-d", seed)
				if err != nil {
					return nil, err
				}
				return parseDomainLines(stdout, seed), nil
			},
		},
	}

	available := make(map[string]bool, len(runners))
	for _, runner := range runners {
		if runner.required == "" {
			available[runner.step] = true
			continue
		}
		_, err := exec.LookPath(runner.required)
		available[runner.step] = err == nil
	}

	var runErr error
	var runErrMu sync.Mutex
	setRunErr := func(err error) {
		runErrMu.Lock()
		defer runErrMu.Unlock()
		if runErr == nil {
			runErr = err
		}
	}

	for _, runner := range runners {
		if !available[runner.step] {
			a.skipStep(runner.step)
			continue
		}
		a.updateStep(runner.step, StepRunning)
	}

	for _, seed := range normalizedSeeds {
		var wg sync.WaitGroup
		for _, runner := range runners {
			r := runner
			if !available[r.step] {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				hosts, err := r.runForSeed(seed)
				if err != nil {
					setRunErr(fmt.Errorf("%s failed for %s: %w", r.step, seed, err))
					return
				}
				appendResults(r.step, hosts)
			}()
		}
		wg.Wait()
		if runErr != nil {
			break
		}
	}

	for _, runner := range runners {
		if !available[runner.step] {
			continue
		}
		if runErr != nil {
			a.updateStep(runner.step, StepError)
			continue
		}
		a.updateStep(runner.step, StepDone)
	}
	if runErr != nil {
		return runErr
	}

	if err := a.runStep(StepConsolidate, func() error {
		var merged []string
		for _, results := range toolResults {
			for host := range results {
				merged = append(merged, host)
			}
		}
		tmpFile, err := os.CreateTemp("", "bflow-consolidate-raw-")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		if _, err := tmpFile.WriteString(strings.Join(merged, "\n")); err != nil {
			tmpFile.Close()
			return err
		}
		if err := tmpFile.Close(); err != nil {
			return err
		}
		return a.runShell(ctx, fmt.Sprintf("cat %s | awk 'NF' | sort -fu > %s", tmpFile.Name(), a.cfg.Lists.Domains))
	}); err != nil {
		return err
	}

	if err := a.runStep(StepHTTPX, func() error {
		_, err := a.buildHTTPDomains(ctx)
		return err
	}); err != nil {
		return err
	}

	if _, err := exec.LookPath("cewl"); err != nil {
		a.skipStep(StepCeWL)
		return nil
	}

	return a.runStep(StepCeWL, func() error {
		targets := readSafeLines(a.httpListOrDefault(a.cfg.Lists.Domains))
		if len(targets) == 0 {
			return nil
		}

		reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
		if err := os.MkdirAll(reconDir, 0o755); err != nil {
			return err
		}

		wordSet := make(map[string]struct{})
		for _, target := range targets {
			stdout, err := a.runCommandCapture(ctx, "cewl", "-q", "-d", "2", "-m", "4", target)
			if err != nil {
				a.logger.Printf("cewl failed for %s: %v", target, err)
				continue
			}
			for _, word := range strings.Split(stdout, "\n") {
				word = strings.TrimSpace(word)
				if word == "" {
					continue
				}
				wordSet[word] = struct{}{}
			}
		}

		words := make([]string, 0, len(wordSet))
		for word := range wordSet {
			words = append(words, word)
		}
		sort.Strings(words)
		out := filepath.Join(reconDir, "cewl_custom_wordlist.txt")
		return os.WriteFile(out, []byte(strings.Join(words, "\n")), 0o644)
	})
}

func (a *App) robots(ctx context.Context, source string) error {
	if source == "" || !fileExists(source) {
		return nil
	}

	targets := append(readSafeLines(a.cfg.Lists.APIDomains), readSafeLines(source)...)
	targets = unique(targets)

	hitsDir := filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsHitsDir)
	noHitsDir := filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsNoHitsDir)

	for _, target := range targets {
		if target == "" {
			continue
		}

		org := strings.TrimSpace(target)

		robotsURL := fmt.Sprintf("%s/robots.txt", strings.TrimRight(org, "/"))
		clean := sanitizeFilename(org)
		robotsPath := filepath.Join(a.cfg.Paths.RobotsDir, fmt.Sprintf("%s.robots.txt", clean))
		urlsPath := filepath.Join(a.cfg.Paths.RobotsDir, fmt.Sprintf("%s.robots.urls", clean))

		req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
		if err != nil {
			return err
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		if err := os.WriteFile(robotsPath, body, 0o644); err != nil {
			return err
		}

		disallows := extractDisallows(string(body))
		if len(disallows) == 0 {
			if err := moveRobotFiles(robotsPath, urlsPath, noHitsDir); err != nil {
				return err
			}
			continue
		}

		if err := os.WriteFile(urlsPath, []byte(strings.Join(disallows, "\n")), 0o644); err != nil {
			return err
		}

		if err := moveRobotFiles(robotsPath, urlsPath, hitsDir); err != nil {
			return err
		}

		if err := appendToFile(filepath.Join(a.cfg.Paths.RobotsDir, "_hits.txt"), strings.Join(disallows, "\n")); err != nil {
			return err
		}

		sitemap := extractSitemap(string(body))
		if sitemap != "" {
			if err := appendToFile(a.cfg.Paths.SitemapsFile, sitemap+"\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *App) buildHTTPDomains(ctx context.Context) (string, error) {
	if !fileExists(a.cfg.Lists.Domains) {
		return "", nil
	}

	dest := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "domains_http")
	if err := os.WriteFile(dest, []byte{}, 0o644); err != nil {
		return "", err
	}

	httpxCmd := fmt.Sprintf("cat %s | awk 'NF{print $1}' | httpx -silent | sed 's#/$##' | anew %s", a.cfg.Lists.Domains, dest)
	if err := a.runShell(ctx, httpxCmd); err != nil {
		httprobeCmd := fmt.Sprintf("cat %s | awk '{print $1}' | httprobe | awk -F/ '{host=$3; scheme=$1} {if (scheme == \"https:\") https[host]=1; all[host]=scheme} END {for (h in all) {if (https[h]) {print \"https://\" h} else {print \"http://\" h}}}' | sort | anew %s", a.cfg.Lists.Domains, dest)
		if fallbackErr := a.runShell(ctx, httprobeCmd); fallbackErr != nil {
			return "", fmt.Errorf("http probing failed: httpx=%v; httprobe=%v", err, fallbackErr)
		}
	}

	a.httpDomainsPath = dest
	return dest, nil
}

func (a *App) httpListOrDefault(path string) string {
	if path == a.cfg.Lists.Domains && a.httpDomainsPath != "" && fileExists(a.httpDomainsPath) {
		return a.httpDomainsPath
	}
	return path
}

func normalizeDorkTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "www.")

	if idx := strings.Index(value, "/"); idx != -1 {
		value = value[:idx]
	}

	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSpace(value)
	return value
}

func normalizeSubdomainSeed(value string) string {
	value = normalizeDorkTarget(value)
	if value == "" {
		return ""
	}

	parts := strings.Split(value, ".")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "*") {
			continue
		}
		clean = append(clean, p)
	}

	if len(clean) < 2 {
		return ""
	}

	return strings.Join(clean, ".")
}

func (a *App) runShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = a.commandOutput()
	cmd.Stderr = a.commandOutput()
	return cmd.Run()
}

func (a *App) runCommandCapture(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = a.commandOutput()
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func parseDomainLines(output, seed string) []string {
	hostPattern := regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9._-]*\.` + regexp.QuoteMeta(seed))
	set := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matches := hostPattern.FindAllString(line, -1)
		for _, match := range matches {
			match = normalizeDorkTarget(match)
			if match == "" {
				continue
			}
			set[match] = struct{}{}
		}
	}
	var out []string
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func parseHostsFromURLs(output, seed string) []string {
	set := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" || !strings.HasSuffix(host, seed) {
			continue
		}
		set[host] = struct{}{}
	}
	var out []string
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func (a *App) fetchCTLHosts(ctx context.Context, seed string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", seed), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}

	set := make(map[string]struct{})
	for _, row := range rows {
		for _, raw := range strings.Split(row.NameValue, "\n") {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, "*."))
			host := normalizeDorkTarget(raw)
			if host == "" || !strings.HasSuffix(host, seed) {
				continue
			}
			set[host] = struct{}{}
		}
	}

	var out []string
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out, nil
}

func (a *App) commandOutput() io.Writer {
	if a.logWriter == nil {
		return os.Stdout
	}
	return io.MultiWriter(os.Stdout, a.logWriter)
}

func readFileLines(path string) ([]string, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func readSafeLines(path string) []string {
	lines, _ := readFileLines(path)
	return lines
}

func unique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}

	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}

	sort.Strings(result)
	return result
}

func sanitizeFilename(input string) string {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "www.")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return strings.ReplaceAll(s, " ", "_")
}

func extractDisallows(body string) []string {
	var result []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") {
			result = append(result, strings.TrimSpace(strings.TrimPrefix(line, "Disallow:")))
		}
	}
	return result
}

func extractSitemap(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "sitemap:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func moveRobotFiles(robotsPath, urlsPath, targetDir string) error {
	if targetDir == "" {
		return errors.New("empty target directory")
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	if err := moveIfExists(robotsPath, filepath.Join(targetDir, filepath.Base(robotsPath))); err != nil {
		return err
	}
	if err := moveIfExists(urlsPath, filepath.Join(targetDir, filepath.Base(urlsPath))); err != nil {
		return err
	}
	return nil
}

func moveIfExists(src, dst string) error {
	if src == "" {
		return nil
	}
	if !fileExists(src) {
		return nil
	}
	return os.Rename(src, dst)
}

func appendToFile(path, content string) error {
	if content == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	return err
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
