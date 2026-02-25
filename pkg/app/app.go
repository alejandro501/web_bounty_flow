package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
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
	StepLoadConfig         = "load-config"
	StepValidateInputs     = "validate-inputs"
	StepDorkOrgs           = "dork-orgs"
	StepSubdomainDiscovery = "subdomain-discovery"
	StepFilterOOS          = "filter-out-of-scope"
	StepResolveLive        = "resolve-live"
	StepDorkLists          = "dork-lists"
	StepGithubDork         = "github-dork"
	StepRobots             = "robots"
	StepSortHTTP           = "sort-http"
	StepURLDiscovery       = "url-discovery"
)

var flowSteps = []Step{
	{ID: StepLoadConfig, Label: "Load flow.yaml and initialize recon runtime."},
	{ID: StepValidateInputs, Label: "Validate required input files (organizations, wildcards, domains, out-of-scope)."},
	{ID: StepDorkOrgs, Label: "Passive recon: generate_dork_links for organizations (API-focused queries)."},
	{ID: StepSubdomainDiscovery, Label: "Subdomain discovery: subfinder + assetfinder + amass on wildcards -> append to domains."},
	{ID: StepFilterOOS, Label: "Passive recon: filter out-of-scope entries from domains."},
	{ID: StepResolveLive, Label: "Live host resolution and API selection: dnsx + httpx/httprobe -> domains_http + apidomains."},
	{ID: StepDorkLists, Label: "Passive recon: generate_dork_links for wildcards, domains, apidomains; move outputs into dorking/ buckets."},
	{ID: StepGithubDork, Label: "GitHub dorking automation (API search + hits)."},
	{ID: StepRobots, Label: "Passive recon: robots fetch + sitemap extraction for wildcards/domains/apidomains."},
	{ID: StepSortHTTP, Label: "Passive recon: sort_http on domains."},
	{ID: StepURLDiscovery, Label: "URL discovery: waybackurls + gau + katana -> consolidated recon URL lists."},
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

	if err := a.runStep(StepValidateInputs, func() error {
		return a.validateReconInputs()
	}); err != nil {
		return err
	}

	a.logger.Println("running passive recon (dorks, robots)")
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
	dorkingRan := false

	if fileExists(a.cfg.Lists.Organizations) {
		if err := a.runStep(StepDorkOrgs, func() error {
			dorkList, err := a.prepareDorkList(a.cfg.Lists.Organizations)
			if err != nil {
				return err
			}
			defer os.Remove(dorkList)

			args := append([]string{"-list", dorkList, "-all"}, a.dorkWordlistArgs(false)...)
			if err := a.runGenerateDorkLinks(ctx, args...); err != nil {
				return err
			}
			dorkingRan = true
			return nil
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepDorkOrgs)
	}

	if fileExists(a.cfg.Lists.Wildcards) {
		if err := a.runStep(StepSubdomainDiscovery, func() error {
			return a.runSubdomainDiscovery(ctx)
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepSubdomainDiscovery)
	}

	if fileExists(a.cfg.Lists.Domains) {
		if err := a.runStep(StepFilterOOS, func() error {
			return a.filterOutOfScope()
		}); err != nil {
			return err
		}

		if err := a.runStep(StepResolveLive, func() error {
			return a.resolveLiveAndAPI(ctx)
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepFilterOOS)
		a.skipStep(StepResolveLive)
	}

	if fileExists(a.cfg.Lists.Wildcards) {
		targetSets := []string{
			a.cfg.Lists.Wildcards,
			a.cfg.Lists.Domains,
			a.cfg.Lists.APIDomains,
		}

		if err := a.runStep(StepDorkLists, func() error {
			for _, listPath := range targetSets {
				if !fileExists(listPath) {
					continue
				}
				useAPI := listPath == a.cfg.Lists.APIDomains
				dorkList, err := a.prepareDorkList(listPath)
				if err != nil {
					return err
				}
				defer os.Remove(dorkList)
				args := append([]string{"-list", dorkList, "-all"}, a.dorkWordlistArgs(useAPI)...)
				if err := a.runGenerateDorkLinks(ctx, args...); err != nil {
					return err
				}
				dorkingRan = true
			}

			if err := a.organizeDorkOutputs(); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return err
		}

		if err := a.runStep(StepGithubDork, func() error {
			return a.githubDorking(ctx)
		}); err != nil {
			return err
		}

		if err := a.runStep(StepRobots, func() error {
			if err := a.robots(ctx, a.cfg.Lists.Wildcards); err != nil {
				return err
			}
			if err := a.robots(ctx, a.httpListOrDefault(a.cfg.Lists.Domains)); err != nil {
				return err
			}
			if err := a.robots(ctx, a.cfg.Lists.APIDomains); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepDorkLists)
		a.skipStep(StepGithubDork)
		a.skipStep(StepRobots)
	}

	if dorkingRan {
		count, err := countRegularFiles(a.cfg.Paths.DorkingDir)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("dorking step produced no output in %s", a.cfg.Paths.DorkingDir)
		}
	}

	if fileExists(a.cfg.Lists.Domains) {
		if err := a.runStep(StepSortHTTP, func() error {
			return a.runShell(ctx, fmt.Sprintf("sort_http -I %s", a.httpListOrDefault(a.cfg.Lists.Domains)))
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepSortHTTP)
	}

	if fileExists(a.cfg.Lists.Domains) {
		if err := a.runStep(StepURLDiscovery, func() error {
			return a.urlDiscovery(ctx)
		}); err != nil {
			return err
		}
	} else {
		a.skipStep(StepURLDiscovery)
	}

	return nil
}

func (a *App) validateReconInputs() error {
	required := []struct {
		label    string
		path     string
		nonEmpty bool
	}{
		{label: "organizations", path: a.cfg.Lists.Organizations, nonEmpty: true},
		{label: "wildcards", path: a.cfg.Lists.Wildcards, nonEmpty: true},
		{label: "domains", path: a.cfg.Lists.Domains, nonEmpty: true},
		{label: "out-of-scope", path: a.cfg.Lists.OutOfScope, nonEmpty: false},
	}

	var missing []string
	var empty []string

	for _, item := range required {
		if !fileExists(item.path) {
			missing = append(missing, fmt.Sprintf("%s (%s)", item.label, item.path))
			continue
		}
		if item.nonEmpty {
			lines := readSafeLines(item.path)
			if len(lines) == 0 {
				empty = append(empty, fmt.Sprintf("%s (%s)", item.label, item.path))
			}
		}
	}

	if len(missing) == 0 && len(empty) == 0 {
		return nil
	}

	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(missing, ", "))
	}
	if len(empty) > 0 {
		parts = append(parts, "empty: "+strings.Join(empty, ", "))
	}

	return fmt.Errorf("required recon input files are not ready; %s", strings.Join(parts, "; "))
}

func (a *App) runSubdomainDiscovery(ctx context.Context) error {
	wildcards, err := a.prepareDorkList(a.cfg.Lists.Wildcards)
	if err != nil {
		return err
	}
	defer os.Remove(wildcards)

	commands := []string{
		fmt.Sprintf("subfinder -dL %s | anew %s", wildcards, a.cfg.Lists.Domains),
		fmt.Sprintf("while IFS= read -r d; do assetfinder --subs-only \"$d\"; done < %s | anew %s", wildcards, a.cfg.Lists.Domains),
		fmt.Sprintf("amass enum -passive -df %s -silent | anew %s", wildcards, a.cfg.Lists.Domains),
	}

	for _, cmd := range commands {
		if err := a.runShell(ctx, cmd); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) resolveLiveAndAPI(ctx context.Context) error {
	if fileExists(a.cfg.Lists.Domains) {
		resolvedPath := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "domains_resolved")
		if err := a.runShell(ctx, fmt.Sprintf("cat %s | awk 'NF' | dnsx -silent | anew %s", a.cfg.Lists.Domains, resolvedPath)); err != nil {
			return err
		}
	}

	httpList, err := a.buildHTTPDomains(ctx)
	if err != nil {
		return err
	}

	source := httpList
	if source == "" {
		source = a.cfg.Lists.Domains
	}

	return a.runShell(ctx, fmt.Sprintf("cat %s | grep -i api | awk '{print $1}' | anew %s", source, a.cfg.Lists.APIDomains))
}

func (a *App) urlDiscovery(ctx context.Context) error {
	reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
	if err := os.MkdirAll(reconDir, 0o755); err != nil {
		return err
	}

	targets := append(readSafeLines(a.httpListOrDefault(a.cfg.Lists.Domains)), readSafeLines(a.cfg.Lists.APIDomains)...)
	targets = unique(targets)
	if len(targets) == 0 {
		a.logger.Println("no targets available for URL discovery")
		return nil
	}

	targetFile, err := os.CreateTemp("", "bflow-url-targets-")
	if err != nil {
		return err
	}
	if _, err := targetFile.WriteString(strings.Join(targets, "\n")); err != nil {
		targetFile.Close()
		return err
	}
	if err := targetFile.Close(); err != nil {
		return err
	}
	defer os.Remove(targetFile.Name())

	waybackOut := filepath.Join(reconDir, "urls_waybackurls.txt")
	gauOut := filepath.Join(reconDir, "urls_gau.txt")
	katanaOut := filepath.Join(reconDir, "urls_katana.txt")
	allOut := filepath.Join(reconDir, "urls_all.txt")
	apiOut := filepath.Join(reconDir, "urls_api_like.txt")

	commands := []string{
		fmt.Sprintf("cat %s | waybackurls | anew %s", targetFile.Name(), waybackOut),
		fmt.Sprintf("cat %s | gau | anew %s", targetFile.Name(), gauOut),
	}

	if _, err := exec.LookPath("katana"); err == nil {
		commands = append(commands, fmt.Sprintf("katana -silent -list %s | anew %s", targetFile.Name(), katanaOut))
	} else {
		a.logger.Println("katana not found; skipping katana URL discovery")
	}

	commands = append(commands,
		fmt.Sprintf("cat %s %s %s 2>/dev/null | awk 'NF' | sort -u > %s", waybackOut, gauOut, katanaOut, allOut),
		fmt.Sprintf("grep -Ei '/(api|graphql|swagger|openapi)|[._-]api[./]' %s | sort -u > %s || true", allOut, apiOut),
	)

	for _, cmd := range commands {
		if err := a.runShell(ctx, cmd); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) organizeDorkOutputs() error {
	categories := map[string]string{
		"shodan":  filepath.Join(a.cfg.Paths.DorkingDir, "shodan"),
		"github":  filepath.Join(a.cfg.Paths.DorkingDir, "github"),
		"google":  filepath.Join(a.cfg.Paths.DorkingDir, "google"),
		"wayback": filepath.Join(a.cfg.Paths.DorkingDir, "wayback"),
	}

	for name, dir := range categories {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		files, err := filepath.Glob(filepath.Join(a.cfg.Paths.DorkingDir, fmt.Sprintf("*%s*", name)))
		if err != nil {
			return err
		}
		for _, file := range files {
			info, err := os.Stat(file)
			if err != nil {
				return err
			}
			if info.IsDir() {
				continue
			}
			if err := os.Rename(file, filepath.Join(dir, filepath.Base(file))); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *App) filterOutOfScope() error {
	if !fileExists(a.cfg.Lists.OutOfScope) || !fileExists(a.cfg.Lists.Domains) {
		return nil
	}

	domains, err := readFileLines(a.cfg.Lists.Domains)
	if err != nil {
		return err
	}

	outOfScope, err := readFileLines(a.cfg.Lists.OutOfScope)
	if err != nil {
		return err
	}

	filtered := []string{}

	for _, domain := range domains {
		if domain == "" || contains(outOfScope, domain) {
			continue
		}
		filtered = append(filtered, domain)
	}

	return os.WriteFile(a.cfg.Lists.Domains, []byte(strings.Join(filtered, "\n")), 0o644)
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

func (a *App) runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = a.commandOutput()
	cmd.Stderr = a.commandOutput()
	return cmd.Run()
}

func (a *App) runCommandWithEnv(ctx context.Context, env []string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = a.commandOutput()
	cmd.Stderr = a.commandOutput()
	return cmd.Run()
}

func (a *App) runGenerateDorkLinks(ctx context.Context, args ...string) error {
	env := []string{fmt.Sprintf("DORKING=%s", a.cfg.Paths.DorkingDir)}
	return a.runCommandWithEnv(ctx, env, "generate_dork_links", args...)
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

func (a *App) dorkWordlistArgs(useAPI bool) []string {
	wl := a.cfg.Wordlists.Dorking
	args := []string{}
	add := func(flag, value string) {
		if value != "" {
			args = append(args, flag, value)
		}
	}
	if useAPI {
		add("--wordlist-github", wl.ApiGithub)
		add("--wordlist-google", wl.ApiGoogle)
		add("--wordlist-shodan", wl.ApiShodan)
		add("--wordlist-wayback", wl.ApiWayback)
	} else {
		add("--wordlist-github", wl.Github)
		add("--wordlist-google", wl.Google)
		add("--wordlist-shodan", wl.Shodan)
		add("--wordlist-wayback", wl.Wayback)
	}
	return args
}

func (a *App) prepareDorkList(path string) (string, error) {
	lines, err := readFileLines(path)
	if err != nil {
		return "", err
	}

	seen := make(map[string]struct{})
	var cleaned []string
	for _, line := range lines {
		normalized := normalizeDorkTarget(line)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		cleaned = append(cleaned, normalized)
	}

	if len(cleaned) == 0 {
		return "", fmt.Errorf("no valid targets for dorking in %s", path)
	}

	tmpFile, err := os.CreateTemp("", "bflow-dork-list-")
	if err != nil {
		return "", err
	}
	if _, err := tmpFile.WriteString(strings.Join(cleaned, "\n")); err != nil {
		tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
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

func (a *App) runShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = a.commandOutput()
	cmd.Stderr = a.commandOutput()
	return cmd.Run()
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

func countRegularFiles(root string) (int, error) {
	if root == "" {
		return 0, errors.New("dorking directory is empty")
	}

	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%s is not a directory", root)
	}

	count := 0
	err = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	return count, nil
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

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
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
