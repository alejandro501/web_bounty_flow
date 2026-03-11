package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultChaosAPIKey = "5b1e13ba-b805-4202-bc9a-1779affb3676"

type chaosDomainItem struct {
	Domain          string   `json:"domain"`
	Label           string   `json:"label,omitempty"`
	SubdomainCount  int      `json:"subdomain_count,omitempty"`
	DistinctIPCount int      `json:"distinct_ip_count,omitempty"`
	Sources         []string `json:"sources,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
}

type chaosGroup struct {
	MainDomain string            `json:"main_domain"`
	Count      int               `json:"count"`
	Items      []chaosDomainItem `json:"items"`
	Error      string            `json:"error,omitempty"`
}

type chaosResponse struct {
	Present      bool         `json:"present"`
	UpdatedAt    string       `json:"updated_at,omitempty"`
	Source       string       `json:"source"`
	TotalDomains int          `json:"total_domains"`
	Groups       []chaosGroup `json:"groups"`
}

func (s *Server) chaosHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mainDomains := s.chaosMainDomains()
	if len(mainDomains) == 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chaosResponse{
			Present:      false,
			Source:       "projectdiscovery-chaos",
			TotalDomains: 0,
			Groups:       []chaosGroup{},
		})
		return
	}

	key := strings.TrimSpace(os.Getenv("BFLOW_CHAOS_API_KEY"))
	if key == "" {
		key = defaultChaosAPIKey
	}

	client := &http.Client{Timeout: 25 * time.Second}
	groups := make([]chaosGroup, 0, len(mainDomains))
	total := 0
	for _, domain := range mainDomains {
		items, err := fetchChaosAssociatedDomains(r.Context(), client, key, domain)
		group := chaosGroup{
			MainDomain: domain,
			Count:      len(items),
			Items:      items,
		}
		if err != nil {
			group.Error = err.Error()
		}
		total += len(items)
		groups = append(groups, group)
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count == groups[j].Count {
			return groups[i].MainDomain < groups[j].MainDomain
		}
		return groups[i].Count > groups[j].Count
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(chaosResponse{
		Present:      total > 0,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		Source:       "projectdiscovery-chaos",
		TotalDomains: total,
		Groups:       groups,
	})
}

func (s *Server) chaosMainDomains() []string {
	candidates := map[string]struct{}{}
	add := func(raw string) {
		domain := normalizeMainDomain(raw)
		if domain == "" {
			return
		}
		candidates[domain] = struct{}{}
	}

	for _, item := range readListLines(s.cfg.Lists.Wildcards) {
		add(item)
	}
	for _, item := range readListLines(s.cfg.Lists.Domains) {
		add(item)
	}
	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	for _, item := range readListLines(filepath.Join(baseDir, "domains_http")) {
		add(item)
	}

	out := make([]string, 0, len(candidates))
	for domain := range candidates {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func normalizeMainDomain(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil {
			value = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		}
	}
	value = strings.TrimSpace(strings.Split(value, "/")[0])
	value = strings.TrimSpace(strings.Split(value, ":")[0])
	if value == "" || !strings.Contains(value, ".") {
		return ""
	}
	return value
}

func fetchChaosAssociatedDomains(ctx context.Context, client *http.Client, key, domain string) ([]chaosDomainItem, error) {
	const endpoint = "https://api.projectdiscovery.io/v1/domain/associated"
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("domain", domain)
	q.Set("limit", "100")
	q.Set("page", "1")
	q.Set("sort", "subdomain_count")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("chaos api %s: %s", domain, strings.TrimSpace(string(raw)))
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	records := extractChaosRecords(parsed)
	out := make([]chaosDomainItem, 0, len(records))
	seen := map[string]struct{}{}
	for _, record := range records {
		item := chaosDomainItem{
			Domain:          strings.TrimSpace(asRawString(record["domain"])),
			Label:           strings.TrimSpace(asRawString(record["label"])),
			SubdomainCount:  asInt(record["subdomain_count"]),
			DistinctIPCount: asInt(record["distinct_ip_count"]),
			Sources:         asStringSlice(record["sources"]),
			Evidence:        asStringSlice(record["evidence"]),
		}
		if item.Domain == "" {
			item.Domain = strings.TrimSpace(asRawString(record["name"]))
		}
		if item.Domain == "" {
			continue
		}
		key := strings.ToLower(item.Domain)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SubdomainCount == out[j].SubdomainCount {
			return out[i].Domain < out[j].Domain
		}
		return out[i].SubdomainCount > out[j].SubdomainCount
	})
	return out, nil
}

func extractChaosRecords(parsed map[string]any) []map[string]any {
	candidates := []string{"data", "domains", "results", "items"}
	for _, key := range candidates {
		raw, ok := parsed[key]
		if !ok {
			continue
		}
		switch arr := raw.(type) {
		case []any:
			out := make([]map[string]any, 0, len(arr))
			for _, item := range arr {
				if row, ok := item.(map[string]any); ok {
					out = append(out, row)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func asInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case float32:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return 0
		}
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}
