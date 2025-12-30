package app

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rojo/hack/web_bounty_flow/pkg/config"
)

// Options are the runtime overrides that used to come from CLI flags.
type Options struct {
	Organization string
	OrgList      string
}

// App coordinates each stage of the bounty flow.
type App struct {
	cfg        *config.Config
	logger     *log.Logger
	httpClient *http.Client
}

// New creates an orchestrator with the provided configuration.
func New(cfg *config.Config, logger *log.Logger) *App {
	return &App{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Run executes the flow in the same logical order as the old shell script.
func (a *App) Run(ctx context.Context, opts Options) error {
	a.logger.Println("preparing directories")
	if err := a.prepareDirectories(); err != nil {
		return err
	}

	a.logger.Println("running passive recon (dorks, robots)")
	if err := a.passiveRecon(ctx, opts); err != nil {
		return err
	}

	a.logger.Println("running documentation fuzzing")
	if err := a.fuzzDocumentation(ctx); err != nil {
		return err
	}

	a.logger.Println("running directory fuzzing")
	if err := a.fuzzDirectories(ctx); err != nil {
		return err
	}

	a.logger.Println("running nmap scans")
	if err := a.nmapScan(ctx); err != nil {
		return err
	}

	a.logger.Println("scanning additional IPs")
	if err := a.scanIPs(ctx); err != nil {
		return err
	}

	a.logger.Println("processing gnmap summaries")
	if err := a.processGnmap(ctx); err != nil {
		return err
	}

	a.logger.Println("running security check utilities")
	if err := a.securityChecks(ctx); err != nil {
		return err
	}

	return nil
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

func (a *App) passiveRecon(ctx context.Context, opts Options) error {
	if fileExists(a.cfg.Lists.Organizations) {
		if err := a.runCommand(ctx, "generate_dork_links", "-oR", a.cfg.Lists.Organizations, "--api"); err != nil {
			return err
		}
	}

	if fileExists(a.cfg.Lists.Wildcards) {
		if err := a.runShell(ctx, fmt.Sprintf("subfinder -dL %s | anew %s", a.cfg.Lists.Wildcards, a.cfg.Lists.Domains)); err != nil {
			return err
		}

		if err := a.filterOutOfScope(); err != nil {
			return err
		}

		if fileExists(a.cfg.Lists.Domains) {
			if err := a.runShell(ctx, fmt.Sprintf("cat %s | grep api | httprobe --prefer-https | anew %s", a.cfg.Lists.Domains, a.cfg.Lists.APIDomains)); err != nil {
				return err
			}
		}

		targetSets := []string{
			a.cfg.Lists.Wildcards,
			a.cfg.Lists.Domains,
			a.cfg.Lists.APIDomains,
		}

		for _, listPath := range targetSets {
			if fileExists(listPath) {
				if err := a.runCommand(ctx, "generate_dork_links", "-L", listPath, "--api"); err != nil {
					return err
				}
			}
		}

		if err := a.organizeDorkOutputs(); err != nil {
			return err
		}

		if err := a.robots(ctx, a.cfg.Lists.Wildcards); err != nil {
			return err
		}
		if err := a.robots(ctx, a.cfg.Lists.Domains); err != nil {
			return err
		}
		if err := a.robots(ctx, a.cfg.Lists.APIDomains); err != nil {
			return err
		}
	}

	if fileExists(a.cfg.Lists.Domains) {
		if err := a.runShell(ctx, fmt.Sprintf("sort_http -I %s", a.cfg.Lists.Domains)); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) fuzzDocumentation(ctx context.Context) error {
	targets := a.collectTargets()
	if len(targets) == 0 {
		a.logger.Println("no targets available for documentation fuzzing")
		return nil
	}

	docDir := filepath.Join(a.cfg.Paths.FuzzingDir, "documentation")

	for _, target := range targets {
		clean := sanitizeFilename(target)
		outputFile := filepath.Join(docDir, fmt.Sprintf("%s.csv", clean))

		args := []string{
			"-u", fmt.Sprintf("%s/FUZZ", target),
			"-w", a.cfg.Wordlists.APIDocs,
			"-mc", "200,301",
			"-o", outputFile,
			"-of", "csv",
		}

		if err := a.runCommand(ctx, "ffuf", args...); err != nil {
			return err
		}

		hits, err := parseFFUFResults(outputFile)
		if err != nil {
			if errors.Is(err, errNoFFUFHits) {
				continue
			}
			return err
		}

		if len(hits) > 0 {
			fp := filepath.Join(a.cfg.Paths.FuzzingDir, "doc_hits")
			f, err := os.OpenFile(fp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			for _, hit := range hits {
				fmt.Fprintf(f, "%s -> %s\n", target, hit.Input)
			}
			_ = f.Close()
		}
	}

	return nil
}

func (a *App) fuzzDirectories(ctx context.Context) error {
	if err := a.buildFuzzWordlist(); err != nil {
		return err
	}

	targetFiles := []string{a.cfg.Lists.APIDomains, a.cfg.Lists.Wildcards}
	var targets []string
	for _, path := range targetFiles {
		lines, err := readFileLines(path)
		if err != nil {
			continue
		}
		targets = append(targets, lines...)
	}

	if len(targets) == 0 {
		a.logger.Println("no targets available for directory fuzzing")
		return nil
	}

	hitsDir := filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir, a.cfg.Paths.FuzzingHitsDir)
	noHitsDir := filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir, a.cfg.Paths.FuzzingNoHitsDir)
	fuzzingHitsFile := filepath.Join(hitsDir, a.cfg.Paths.AllHitsFile)

	for _, target := range targets {
		outputFile := filepath.Join(a.cfg.Paths.FuzzingDir, a.cfg.Paths.FFUFDir, fmt.Sprintf("%s.csv", sanitizeFilename(target)))

		args := []string{
			"-u", fmt.Sprintf("%s/FUZZ", target),
			"-w", filepath.Join(a.cfg.Paths.FuzzingDir, "fuzzme"),
			"-mc", "200,301",
			"-p", "0.2",
			"-o", outputFile,
			"-of", "csv",
		}

		if err := a.runCommand(ctx, "ffuf", args...); err != nil {
			return err
		}

		hits, err := parseFFUFResults(outputFile)
		if errors.Is(err, errNoFFUFHits) {
			if err := os.Rename(outputFile, filepath.Join(noHitsDir, fmt.Sprintf("%s.csv", sanitizeFilename(target)))); err != nil {
				return err
			}
			continue
		}

		if err != nil {
			return err
		}

		if len(hits) > 0 {
			if err := os.WriteFile(filepath.Join(hitsDir, fmt.Sprintf("%s.txt", sanitizeFilename(target))), []byte(strings.Join(flattenInputs(hits), "\n")), 0o644); err != nil {
				return err
			}

			f, err := os.OpenFile(fuzzingHitsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			for _, hit := range hits {
				fmt.Fprintf(f, "%s\n", hit.Input)
			}
			_ = f.Close()
		}
	}

	return nil
}

func (a *App) nmapScan(ctx context.Context) error {
	if fileExists(a.cfg.Lists.Domains) {
		if err := a.scanFile(ctx, a.cfg.Lists.Domains); err != nil {
			return err
		}
	}

	if fileExists(a.cfg.Lists.APIDomains) {
		if err := a.scanFile(ctx, a.cfg.Lists.APIDomains); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) scanIPs(ctx context.Context) error {
	if !fileExists(a.cfg.Lists.IPs) {
		return nil
	}

	return a.scanFile(ctx, a.cfg.Lists.IPs)
}

func (a *App) scanFile(ctx context.Context, path string) error {
	targets, err := readFileLines(path)
	if err != nil {
		return err
	}

	for _, target := range targets {
		if target == "" {
			continue
		}
		clean := sanitizeFilename(target)
		outputBase := filepath.Join(a.cfg.Paths.NmapDir, clean)
		if err := a.runCommand(ctx, "nmap", "-p-", target, "-oA", outputBase); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) processGnmap(ctx context.Context) error {
	if !a.cfg.NmapSummary.Enable {
		a.logger.Println("nmap summary processing disabled in config")
		return nil
	}

	summary := []string{}
	pointers := []string{}
	services := map[string]struct{}{}

	files, err := filepath.Glob(filepath.Join(a.cfg.Paths.NmapDir, "*.gnmap"))
	if err != nil {
		return err
	}

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		target := extractField(data, `Nmap .* scan initiated .* as: nmap .* (\\S+)`)
		host := extractField(data, `Host: (\\S+)`)

		openPorts := extractList(data, `(\\d+)/open`)
		servicesFound := extractServiceLines(data)

		summary = append(summary, fmt.Sprintf("-------\nTarget: %s\nHost: %s\nOpen ports: %s\nServices:\n%s\n", target, host, strings.Join(openPorts, ","), strings.Join(servicesFound, "\n")))

		var interesting []string
		for _, service := range servicesFound {
			parts := strings.Fields(service)
			if len(parts) < 2 {
				continue
			}
			port := strings.Split(parts[0], "/")[0]
			name := parts[1]
			if contains(a.cfg.NmapSummary.InterestingServices, name) || contains(a.cfg.NmapSummary.InterestingPorts, port) {
				interesting = append(interesting, service)
			}
			services[service] = struct{}{}
		}

		if len(interesting) > 0 {
			pointers = append(pointers, fmt.Sprintf("Interesting services on %s (%s):\n%s\n", host, target, strings.Join(interesting, "\n")))
		}
	}

	if err := os.WriteFile(a.cfg.NmapSummary.SummaryFile, []byte(strings.Join(summary, "\n")), 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(a.cfg.NmapSummary.PointersFile, []byte(strings.Join(pointers, "\n")), 0o644); err != nil {
		return err
	}

	serviceList := make([]string, 0, len(services))
	for svc := range services {
		serviceList = append(serviceList, svc)
	}
	sort.Strings(serviceList)

	if err := os.WriteFile(a.cfg.NmapSummary.ServicesFile, []byte(strings.Join(serviceList, "\n")), 0o644); err != nil {
		return err
	}

	if len(serviceList) > 0 {
		var builder strings.Builder
		for _, svc := range serviceList {
			builder.WriteString(fmt.Sprintf("Searching for %s\n", svc))
			if err := a.runCommand(ctx, "searchsploit", svc); err != nil {
				a.logger.Printf("searchsploit failed for %s: %v", svc, err)
			}
			builder.WriteString("-----------------------------\n")
		}
		if err := os.WriteFile(a.cfg.NmapSummary.SearchsploitFile, []byte(builder.String()), 0o644); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) securityChecks(ctx context.Context) error {
	domainArg := a.cfg.Lists.Domains
	if domainArg == "" {
		return errors.New("domains list is required for security checks")
	}

	commands := [][]string{
		{"./utils/toxicache.sh", "--input", domainArg},
		{"./utils/hop_by_hop_checker.py", "--l", domainArg},
		{"python3", "./utils/request_smuggling.py", "--file", domainArg},
		{"./utils/h2csmuggler.sh", "--input", domainArg},
		{"./utils/ssi_esi.sh", "--input", domainArg},
		{"python3", "./utils/cloudflare.py", "--file", domainArg},
	}

	for _, cmd := range commands {
		if err := a.runCommand(ctx, cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}

	return nil
}

func (a *App) buildFuzzWordlist() error {
	words := make(map[string]struct{})
	sources := []string{
		a.cfg.Wordlists.APIWild501,
		a.cfg.Wordlists.SecListAPILongest,
		a.cfg.Wordlists.CustomProjectSpecific,
	}

	for _, source := range sources {
		lines, err := readFileLines(source)
		if err != nil {
			continue
		}
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			words[trimmed] = struct{}{}
		}
	}

	dest := filepath.Join(a.cfg.Paths.FuzzingDir, "fuzzme")
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	for word := range words {
		fmt.Fprintln(f, word)
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
		files, err := filepath.Glob(fmt.Sprintf("*%s*", name))
		if err != nil {
			return err
		}
		for _, file := range files {
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

func (a *App) collectTargets() []string {
	var targets []string

	for _, path := range []string{a.cfg.Lists.Organizations, a.cfg.Lists.Wildcards, a.cfg.Lists.APIDomains} {
		if fileExists(path) {
			targets = append(targets, readSafeLines(path)...)
		}
	}

	return unique(targets)
}

func (a *App) runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (a *App) runShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var errNoFFUFHits = errors.New("no ffuf hits")

type ffufHit struct {
	Input string
}

func parseFFUFResults(path string) ([]ffufHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	if _, err := r.Read(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errNoFFUFHits
		}
		return nil, err
	}

	var hits []ffufHit
	for {
		record, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if len(record) < 2 {
			continue
		}

		hits = append(hits, ffufHit{Input: record[1]})
	}

	if len(hits) == 0 {
		return nil, errNoFFUFHits
	}

	return hits, nil
}

func flattenInputs(hits []ffufHit) []string {
	result := make([]string, len(hits))
	for i, hit := range hits {
		result[i] = hit.Input
	}
	return result
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

func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

func extractField(data []byte, pattern string) string {
	re := regexp.MustCompile(pattern)
	if match := re.FindSubmatch(data); len(match) > 1 {
		return string(match[1])
	}
	return ""
}

func extractList(data []byte, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllSubmatch(data, -1)
	var result []string
	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, string(match[1]))
		}
	}
	return result
}

func extractServiceLines(data []byte) []string {
	re := regexp.MustCompile(`\d+/open/[^/]+//[^/]+//[^/]+`)
	matches := re.FindAllString(string(data), -1)
	return matches
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
	if err := os.Rename(robotsPath, filepath.Join(targetDir, filepath.Base(robotsPath))); err != nil {
		return err
	}
	if err := os.Rename(urlsPath, filepath.Join(targetDir, filepath.Base(urlsPath))); err != nil {
		return err
	}
	return nil
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
