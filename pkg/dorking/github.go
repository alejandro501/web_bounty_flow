package dorking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	githubSearchURL = "https://api.github.com/search/code"
	githubRateURL   = "https://api.github.com/rate_limit"
)

type GithubOptions struct {
	OutputDir   string
	Tokens      []Token
	Logger      logger
	UpdateToken func(tokenID string, used time.Time, lastErr string)
}

type Token struct {
	ID    string
	Value string
}

type logger interface {
	Println(...interface{})
	Printf(string, ...interface{})
}

type githubSearchResponse struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		HTMLURL string `json:"html_url"`
	} `json:"items"`
}

func RunGithubSearch(ctx context.Context, opts GithubOptions) error {
	log := opts.Logger
	if log == nil {
		log = noopLogger{}
	}
	if len(opts.Tokens) == 0 {
		return errors.New("no github tokens available")
	}
	if opts.OutputDir == "" {
		return errors.New("github output dir is required")
	}
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return err
	}

	files, err := githubSearchFiles(opts.OutputDir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Println("no github dork files found")
		return nil
	}

	hitsMinimal := filepath.Join(opts.OutputDir, "_hits.txt")
	hitsVerbose := filepath.Join(opts.OutputDir, "_hits_verbose.txt")
	if err := os.WriteFile(hitsMinimal, []byte{}, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(hitsVerbose, []byte{}, 0o644); err != nil {
		return err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	rotator := newTokenRotator(opts.Tokens, opts.UpdateToken)

	for _, file := range files {
		if err := processGithubFile(ctx, client, file, hitsMinimal, hitsVerbose, rotator, log); err != nil {
			return err
		}
		if err := moveToProcessed(file); err != nil {
			log.Printf("failed to move %s: %v", file, err)
		}
	}

	log.Println("github dorking completed")
	return nil
}

func githubSearchFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".txt") {
			continue
		}
		if name == "_hits.txt" || name == "_hits_verbose.txt" || name == "_github_token.txt" {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files, nil
}

func processGithubFile(ctx context.Context, client *http.Client, path, hitsMinimal, hitsVerbose string, rotator *tokenRotator, log logger) error {
	log.Printf("processing github dork file: %s", filepath.Base(path))
	urls, err := extractGithubURLs(path)
	if err != nil {
		return err
	}
	for _, u := range urls {
		query := extractGithubQuery(u)
		if query == "" {
			continue
		}
		if err := waitForRateLimit(ctx, client, rotator, log); err != nil {
			return err
		}
		result, err := githubSearch(ctx, client, rotator, query)
		if err != nil {
			log.Printf("github search failed for %s: %v", query, err)
			continue
		}
		if result.TotalCount > 0 {
			if err := appendVerboseHit(hitsVerbose, query, result); err != nil {
				return err
			}
			if err := appendMinimalHit(hitsMinimal, u); err != nil {
				return err
			}
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func extractGithubURLs(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(raw), "\n")
	urls := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "https://github.com/search?q=") {
			urls[line] = struct{}{}
		}
	}
	var out []string
	for u := range urls {
		out = append(out, u)
	}
	return out, nil
}

func extractGithubQuery(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	query := parsed.Query().Get("q")
	query, _ = url.QueryUnescape(query)
	re := regexp.MustCompile(`in:url"?([^\s"]+)"?`)
	query = re.ReplaceAllString(query, "in:url:$1")
	return query
}

func githubSearch(ctx context.Context, client *http.Client, rotator *tokenRotator, query string) (*githubSearchResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubSearchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+rotator.current().Value)

	q := req.URL.Query()
	q.Set("q", query)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		rotator.markError(err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		rotator.rotate("unauthorized")
		return githubSearch(ctx, client, rotator, query)
	}
	if resp.StatusCode == http.StatusForbidden {
		rotator.rotate("rate_limited")
		return githubSearch(ctx, client, rotator, query)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github search failed: %s", strings.TrimSpace(string(body)))
	}

	var out githubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	rotator.markUsed()
	return &out, nil
}

func waitForRateLimit(ctx context.Context, client *http.Client, rotator *tokenRotator, log logger) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubRateURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Authorization", "Bearer "+rotator.current().Value)

	resp, err := client.Do(req)
	if err != nil {
		rotator.markError(err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		rotator.rotate("unauthorized")
		return waitForRateLimit(ctx, client, rotator, log)
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var payload struct {
		Resources struct {
			Search struct {
				Remaining int   `json:"remaining"`
				Reset     int64 `json:"reset"`
			} `json:"search"`
		} `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	if payload.Resources.Search.Remaining > 1 {
		return nil
	}

	reset := time.Unix(payload.Resources.Search.Reset, 0)
	wait := time.Until(reset) + 5*time.Second
	if wait < 0 {
		return nil
	}
	log.Printf("github rate limit reached, sleeping %s", wait.Round(time.Second))
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func appendVerboseHit(path, query string, result *githubSearchResponse) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "\n=== HIT ===\nQuery: %s\nResults: %d\n", query, result.TotalCount); err != nil {
		return err
	}
	for _, item := range result.Items {
		if _, err := fmt.Fprintf(f, "- %s\n", item.HTMLURL); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339))
	return err
}

func appendMinimalHit(path, url string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", url)
	return err
}

func moveToProcessed(path string) error {
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	destDir := filepath.Join(dir, "processed")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(destDir, base))
}

type tokenRotator struct {
	tokens     []Token
	index      int
	updateFunc func(tokenID string, used time.Time, lastErr string)
}

type noopLogger struct{}

func (noopLogger) Println(...interface{})          {}
func (noopLogger) Printf(string, ...interface{})  {}

func newTokenRotator(tokens []Token, update func(tokenID string, used time.Time, lastErr string)) *tokenRotator {
	return &tokenRotator{tokens: tokens, updateFunc: update}
}

func (t *tokenRotator) current() Token {
	if len(t.tokens) == 0 {
		return Token{}
	}
	if t.index >= len(t.tokens) {
		t.index = 0
	}
	return t.tokens[t.index]
}

func (t *tokenRotator) rotate(reason string) {
	if len(t.tokens) == 0 {
		return
	}
	t.index = (t.index + 1) % len(t.tokens)
	if t.updateFunc != nil {
		t.updateFunc(t.current().ID, time.Now(), reason)
	}
}

func (t *tokenRotator) markUsed() {
	if t.updateFunc != nil {
		t.updateFunc(t.current().ID, time.Now(), "")
	}
}

func (t *tokenRotator) markError(err error) {
	if t.updateFunc == nil {
		return
	}
	msg := "unknown"
	if err != nil {
		msg = err.Error()
	}
	t.updateFunc(t.current().ID, time.Now(), msg)
}
