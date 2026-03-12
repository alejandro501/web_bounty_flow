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
	"sync"
	"time"
)

const defaultChaosAPIKey = "5b1e13ba-b805-4202-bc9a-1779affb3676"
const chaosMaxMainDomains = 12
const chaosParallelism = 2
const chaosAssocCacheTTL = 10 * time.Minute
const chaosDNSCacheTTL = 10 * time.Minute

var (
	chaosAssocCacheMu sync.Mutex
	chaosAssocCache   = map[string]chaosAssocCacheEntry{}
	chaosDNSCacheMu   sync.Mutex
	chaosDNSCache     = map[string]chaosDNSCacheEntry{}
)

type chaosAssocCacheEntry struct {
	Data      chaosAssociatedData
	FetchedAt time.Time
}

type chaosDNSCacheEntry struct {
	Data      chaosDNSData
	FetchedAt time.Time
}

type chaosDomainItem struct {
	Domain          string   `json:"domain"`
	Label           string   `json:"label,omitempty"`
	SubdomainCount  int      `json:"subdomain_count,omitempty"`
	DistinctIPCount int      `json:"distinct_ip_count,omitempty"`
	Sources         []string `json:"sources,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
}

type chaosGroup struct {
	MainDomain          string            `json:"main_domain"`
	Count               int               `json:"count"`
	Items               []chaosDomainItem `json:"items"`
	Sources             []string          `json:"sources,omitempty"`
	SourceCounts        map[string]int    `json:"source_counts,omitempty"`
	DNSTotalSubdomains  int               `json:"dns_total_subdomains,omitempty"`
	DNSSampleSubdomains []string          `json:"dns_sample_subdomains,omitempty"`
	Error               string            `json:"error,omitempty"`
	DNSError            string            `json:"dns_error,omitempty"`
}

type chaosResponse struct {
	Present      bool         `json:"present"`
	UpdatedAt    string       `json:"updated_at,omitempty"`
	Source       string       `json:"source"`
	TotalDomains int          `json:"total_domains"`
	TotalDNSSubs int          `json:"total_dns_subdomains"`
	Groups       []chaosGroup `json:"groups"`
}

func (s *Server) chaosHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mainDomains := s.chaosMainDomains()
	if len(mainDomains) > chaosMaxMainDomains {
		mainDomains = mainDomains[:chaosMaxMainDomains]
	}
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

	client := &http.Client{Timeout: 10 * time.Second}
	groups := make([]chaosGroup, len(mainDomains))
	sem := make(chan struct{}, chaosParallelism)
	var wg sync.WaitGroup
	for idx, domain := range mainDomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, d string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			assoc, err := fetchChaosAssociatedDomainsCached(ctx, client, key, d)
			dnsInfo, dnsErr := fetchChaosDNSDomainDataCached(ctx, client, key, d)
			group := chaosGroup{
				MainDomain:          d,
				Count:               len(assoc.Items),
				Items:               assoc.Items,
				Sources:             assoc.Sources,
				SourceCounts:        assoc.SourceCounts,
				DNSTotalSubdomains:  dnsInfo.TotalSubdomains,
				DNSSampleSubdomains: dnsInfo.SampleSubdomains,
			}
			if err != nil {
				group.Error = err.Error()
			}
			if dnsErr != nil {
				group.DNSError = dnsErr.Error()
			}
			groups[i] = group
		}(idx, domain)
	}
	wg.Wait()
	total := 0
	totalDNS := 0
	for _, group := range groups {
		total += group.Count
		totalDNS += group.DNSTotalSubdomains
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
		TotalDNSSubs: totalDNS,
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
	// Fallback only when wildcards are missing.
	if len(candidates) == 0 {
		baseDir := filepath.Dir(s.cfg.Lists.Domains)
		for _, item := range readListLines(filepath.Join(baseDir, "domains_http")) {
			add(item)
		}
		for _, item := range readListLines(s.cfg.Lists.Domains) {
			add(item)
		}
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

type chaosAssociatedData struct {
	Items        []chaosDomainItem
	Sources      []string
	SourceCounts map[string]int
}

func fetchChaosAssociatedDomainsCached(ctx context.Context, client *http.Client, key, domain string) (chaosAssociatedData, error) {
	cacheKey := strings.ToLower(strings.TrimSpace(domain))
	now := time.Now()
	chaosAssocCacheMu.Lock()
	if cached, ok := chaosAssocCache[cacheKey]; ok && now.Sub(cached.FetchedAt) < chaosAssocCacheTTL {
		chaosAssocCacheMu.Unlock()
		return cached.Data, nil
	}
	chaosAssocCacheMu.Unlock()

	data, err := fetchChaosAssociatedDomains(ctx, client, key, domain)
	if err != nil {
		// If API is rate-limited, return stale cache when available.
		if strings.Contains(strings.ToLower(err.Error()), "too many requests") {
			chaosAssocCacheMu.Lock()
			if cached, ok := chaosAssocCache[cacheKey]; ok {
				chaosAssocCacheMu.Unlock()
				return cached.Data, nil
			}
			chaosAssocCacheMu.Unlock()
		}
		return data, err
	}
	chaosAssocCacheMu.Lock()
	chaosAssocCache[cacheKey] = chaosAssocCacheEntry{Data: data, FetchedAt: now}
	chaosAssocCacheMu.Unlock()
	return data, nil
}

func fetchChaosAssociatedDomains(ctx context.Context, client *http.Client, key, domain string) (chaosAssociatedData, error) {
	const endpoint = "https://api.projectdiscovery.io/v1/domain/associated"
	out := chaosAssociatedData{SourceCounts: map[string]int{}}
	u, err := url.Parse(endpoint)
	if err != nil {
		return out, err
	}
	q := u.Query()
	q.Set("domain", domain)
	q.Set("limit", "20")
	q.Set("page", "1")
	q.Set("sort", "subdomain_count")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")

	var raw []byte
	var resp *http.Response
	var doErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, doErr = client.Do(req.WithContext(ctx))
		if doErr != nil {
			return out, doErr
		}
		raw, _ = io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			if attempt < 2 {
				select {
				case <-ctx.Done():
					return out, ctx.Err()
				case <-time.After(time.Duration(attempt+1) * 1200 * time.Millisecond):
				}
				continue
			}
		}
		break
	}
	if resp == nil {
		return out, fmt.Errorf("chaos api %s: empty response", domain)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("chaos api %s: %s", domain, strings.TrimSpace(string(raw)))
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return out, err
	}
	out.Sources = asStringSlice(parsed["sources"])
	if counts, ok := parsed["sources_count"].(map[string]any); ok {
		for k, v := range counts {
			out.SourceCounts[k] = asInt(v)
		}
	}
	records := extractChaosRecords(parsed)
	items := make([]chaosDomainItem, 0, len(records))
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
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].SubdomainCount == items[j].SubdomainCount {
			return items[i].Domain < items[j].Domain
		}
		return items[i].SubdomainCount > items[j].SubdomainCount
	})
	out.Items = items
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

type chaosDNSData struct {
	TotalSubdomains  int
	SampleSubdomains []string
}

func fetchChaosDNSDomainDataCached(ctx context.Context, client *http.Client, key, domain string) (chaosDNSData, error) {
	cacheKey := strings.ToLower(strings.TrimSpace(domain))
	now := time.Now()
	chaosDNSCacheMu.Lock()
	if cached, ok := chaosDNSCache[cacheKey]; ok && now.Sub(cached.FetchedAt) < chaosDNSCacheTTL {
		chaosDNSCacheMu.Unlock()
		return cached.Data, nil
	}
	chaosDNSCacheMu.Unlock()

	data, err := fetchChaosDNSDomainData(ctx, client, key, domain)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "too many requests") {
			chaosDNSCacheMu.Lock()
			if cached, ok := chaosDNSCache[cacheKey]; ok {
				chaosDNSCacheMu.Unlock()
				return cached.Data, nil
			}
			chaosDNSCacheMu.Unlock()
		}
		return data, err
	}
	chaosDNSCacheMu.Lock()
	chaosDNSCache[cacheKey] = chaosDNSCacheEntry{Data: data, FetchedAt: now}
	chaosDNSCacheMu.Unlock()
	return data, nil
}

func fetchChaosDNSDomainData(ctx context.Context, client *http.Client, key, domain string) (chaosDNSData, error) {
	out := chaosDNSData{}
	base := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s", url.PathEscape(domain))
	reqCount, err := http.NewRequest(http.MethodGet, base, nil)
	if err != nil {
		return out, err
	}
	reqCount.Header.Set("Authorization", key)
	reqCount.Header.Set("Accept", "application/json")
	respCount, err := client.Do(reqCount.WithContext(ctx))
	if err != nil {
		return out, err
	}
	defer respCount.Body.Close()
	rawCount, _ := io.ReadAll(io.LimitReader(respCount.Body, 1<<20))
	if respCount.StatusCode < 200 || respCount.StatusCode >= 300 {
		return out, fmt.Errorf("dns api %s: %s", domain, strings.TrimSpace(string(rawCount)))
	}
	var countParsed map[string]any
	if err := json.Unmarshal(rawCount, &countParsed); err != nil {
		return out, err
	}
	out.TotalSubdomains = asInt(countParsed["subdomains"])

	reqList, err := http.NewRequest(http.MethodGet, base+"/subdomains", nil)
	if err != nil {
		return out, err
	}
	reqList.Header.Set("Authorization", key)
	reqList.Header.Set("Accept", "application/json")
	respList, err := client.Do(reqList.WithContext(ctx))
	if err != nil {
		return out, err
	}
	defer respList.Body.Close()
	rawList, _ := io.ReadAll(io.LimitReader(respList.Body, 2<<20))
	if respList.StatusCode < 200 || respList.StatusCode >= 300 {
		return out, fmt.Errorf("dns api %s subdomains: %s", domain, strings.TrimSpace(string(rawList)))
	}
	var listParsed map[string]any
	if err := json.Unmarshal(rawList, &listParsed); err != nil {
		return out, err
	}
	subs := asStringSlice(listParsed["subdomains"])
	sample := make([]string, 0, len(subs))
	for _, sub := range subs {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		sample = append(sample, sub)
		if len(sample) >= 50 {
			break
		}
	}
	out.SampleSubdomains = sample
	return out, nil
}
