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
	{ID: StepConsolidate, Label: "Consolidate all discovered hosts and remove duplicates."},
	{ID: StepHTTPX, Label: "Probe consolidated hosts with httpx for live web servers."},
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
	cfg             *config.Config
	logger          *log.Logger
	httpClient      *http.Client
	httpDomainsPath string
	liveCSVPath     string
	logWriter       io.Writer
	stepUpdate      func(id string, status StepStatus)
	configStore     *configstore.Store
}

type liveWebserverRecord struct {
	URL           string
	StatusCode    int
	Title         string
	WebServer     string
	Technologies  []string
	ContentLength int
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
		StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepConsolidate, StepHTTPX, StepCeWL, StepFuzzDocs, StepFuzzDirs,
	} {
		a.updateStep(step, StepPending)
	}

	if !fileExists(a.cfg.Lists.Wildcards) || len(readSafeLines(a.cfg.Lists.Wildcards)) == 0 {
		for _, step := range []string{
			StepAmass, StepSublist3r, StepAssetfinder, StepGAU, StepCTL, StepSubfinder, StepConsolidate, StepHTTPX, StepCeWL, StepFuzzDocs, StepFuzzDirs,
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
	combinedAmassJSON := filepath.Join(amassDir, "amass_enum.jsonl")
	if err := os.MkdirAll(amassDir, 0o755); err != nil {
		return err
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
		runForSeed func(seed string) ([]string, error)
	}

	var amassFileMu sync.Mutex
	runners := []toolRunner{
		{
			step:     StepAmass,
			required: "amass",
			runForSeed: func(seed string) ([]string, error) {
				seedFile := sanitizeFilename(seed)
				seedPrefix := filepath.Join(amassDir, seedFile)
				seedJSON := seedPrefix + ".json"
				seedText := seedPrefix + ".txt"
				_, err := a.runCommandCapture(ctx, "amass", "enum", "-passive", "-d", seed, "-oA", seedPrefix)
				if err != nil {
					return nil, err
				}
				hosts := parseDomainLines(strings.Join(readSafeLines(seedText), "\n"), seed)
				if fileExists(seedJSON) {
					rawJSON, readErr := os.ReadFile(seedJSON)
					if readErr != nil {
						return nil, readErr
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
				hosts, err := r.runForSeed(seed)
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

func normalizeHTTPSTargets(inputs []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range inputs {
		host := normalizeDorkTarget(raw)
		if host == "" {
			continue
		}
		target := "https://" + host
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
		u := strings.TrimSpace(rec[urlIdx])
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
	csvPath := filepath.Join(filepath.Dir(a.cfg.Lists.Domains), "live-webservers.csv")
	if err := os.WriteFile(dest, []byte{}, 0o644); err != nil {
		return "", err
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
		httprobeCmd := fmt.Sprintf("cat %s | awk '{print $1}' | httprobe | awk -F/ '{host=$3; scheme=$1} {if (scheme == \"https:\") https[host]=1; all[host]=scheme} END {for (h in all) {if (https[h]) {print \"https://\" h} else {print \"http://\" h}}}' | sort | anew %s", a.cfg.Lists.Domains, dest)
		if fallbackErr := a.runShell(ctx, httprobeCmd); fallbackErr != nil {
			return "", fmt.Errorf("http probing failed: httpx=%v; httprobe=%v", err, fallbackErr)
		}

		urls := readSafeLines(dest)
		var fallbackRows []liveWebserverRecord
		for _, u := range urls {
			u = strings.TrimSpace(strings.TrimRight(u, "/"))
			if u == "" {
				continue
			}
			fallbackRows = append(fallbackRows, liveWebserverRecord{URL: u})
		}
		if err := a.writeLiveWebserversCSV(csvPath, fallbackRows); err != nil {
			return "", err
		}
		a.liveCSVPath = csvPath
		a.httpDomainsPath = dest
		return dest, nil
	}

	rows := parseHTTPXJSONRecords(stdout)
	urlSet := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		u := strings.TrimSpace(strings.TrimRight(row.URL, "/"))
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
	if err := os.WriteFile(dest, []byte(strings.Join(urls, "\n")), 0o644); err != nil {
		return "", err
	}
	if err := a.writeLiveWebserversCSV(csvPath, rows); err != nil {
		return "", err
	}

	a.liveCSVPath = csvPath
	a.httpDomainsPath = dest
	return dest, nil
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
			apiSet[host] = struct{}{}
		}
	}

	apiDomains := make([]string, 0, len(apiSet))
	for host := range apiSet {
		apiDomains = append(apiDomains, host)
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
	cmd.Stdout = &stdout
	cmd.Stderr = a.commandOutput()
	if err := cmd.Run(); err != nil {
		a.logger.Printf("exec failed: %s (%s): %v", name, time.Since(start).Round(time.Second), err)
		return "", err
	}
	a.logger.Printf("exec done: %s (%s)", name, time.Since(start).Round(time.Second))
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
