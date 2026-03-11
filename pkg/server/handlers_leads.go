package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type leadStatePayload struct {
	ID     string `json:"id"`
	Done   *bool  `json:"done,omitempty"`
	Bucket string `json:"bucket,omitempty"`
	Action string `json:"action,omitempty"`
}

type leadReplayPayload struct {
	ID     string `json:"id"`
	URL    string `json:"url,omitempty"`
	Method string `json:"method,omitempty"`
}

func (s *Server) leadStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload leadStatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(payload.ID)
	if id == "" {
		http.Error(w, "lead id is required", http.StatusBadRequest)
		return
	}

	s.leadStateMu.Lock()
	defer s.leadStateMu.Unlock()
	current := s.leadStates[id]
	if strings.EqualFold(strings.TrimSpace(payload.Action), "delete") {
		current.Bucket = "deleted"
		current.Done = true
	} else {
		bucket, ok := normalizeLeadBucket(payload.Bucket)
		if !ok {
			http.Error(w, "invalid bucket", http.StatusBadRequest)
			return
		}
		if payload.Bucket != "" || strings.EqualFold(strings.TrimSpace(payload.Bucket), "active") {
			current.Bucket = bucket
		}
		if payload.Done != nil {
			current.Done = *payload.Done
		}
	}
	current.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if current.Bucket == "" && !current.Done {
		delete(s.leadStates, id)
	} else {
		s.leadStates[id] = current
	}
	if err := s.saveLeadStatesLocked(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(current)
}

func (s *Server) leadReplayHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload leadReplayPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(payload.ID)
	if id == "" {
		http.Error(w, "lead id is required", http.StatusBadRequest)
		return
	}
	leads, _, err := s.collectLeads()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var selected *leadItem
	for i := range leads {
		if leads[i].ID == id {
			selected = &leads[i]
			break
		}
	}
	if selected == nil {
		http.Error(w, "lead not found", http.StatusNotFound)
		return
	}
	targetURL := strings.TrimSpace(payload.URL)
	if targetURL == "" {
		targetURL = strings.TrimSpace(firstNonEmptyString(
			asRawString(selected.Evidence["mutated_url"]),
			asRawString(selected.Evidence["endpoint"]),
			selected.Target,
		))
	}
	if targetURL == "" {
		http.Error(w, "lead has no replayable url", http.StatusBadRequest)
		return
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		http.Error(w, "invalid replay url", http.StatusBadRequest)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(payload.Method))
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(firstNonEmptyString(asRawString(selected.Evidence["method"]), "GET")))
	}
	if method == "" {
		method = http.MethodGet
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	proxyEnabled, proxyURL := s.currentProxyURL()
	client := &http.Client{Timeout: 20 * time.Second}
	if proxyEnabled {
		proxyParsed, parseErr := url.Parse(proxyURL)
		if parseErr == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyParsed)}
		}
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	snippet, _ := readBodySnippet(resp.Body, 2048)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":                selected.ID,
		"url":               parsedURL.String(),
		"method":            method,
		"status_code":       resp.StatusCode,
		"content_type":      strings.TrimSpace(resp.Header.Get("Content-Type")),
		"duration_ms":       time.Since(started).Milliseconds(),
		"proxy_enabled":     proxyEnabled,
		"proxy_url":         proxyURL,
		"response_snippet":  snippet,
		"response_location": strings.TrimSpace(resp.Header.Get("Location")),
	})
}

func (s *Server) collectLeads() ([]leadItem, time.Time, error) {
	baseDir := filepath.Dir(s.cfg.Lists.Domains)
	fuzzDir := filepath.Join(baseDir, "fuzzing")
	roots := readListLines(s.cfg.Lists.Wildcards)
	specs := []struct {
		category string
		source   string
		path     string
	}{
		{category: "injection", source: "injection/sqli_hits.jsonl", path: filepath.Join(fuzzDir, "injection", "sqli_hits.jsonl")},
		{category: "injection", source: "injection/nosqli_hits.jsonl", path: filepath.Join(fuzzDir, "injection", "nosqli_hits.jsonl")},
		{category: "injection", source: "injection/xpath_hits.jsonl", path: filepath.Join(fuzzDir, "injection", "xpath_hits.jsonl")},
		{category: "injection", source: "injection/ldap_hits.jsonl", path: filepath.Join(fuzzDir, "injection", "ldap_hits.jsonl")},
		{category: "server-input", source: "server-input/os_command_hits.jsonl", path: filepath.Join(fuzzDir, "server-input", "os_command_hits.jsonl")},
		{category: "server-input", source: "server-input/path_traversal_hits.jsonl", path: filepath.Join(fuzzDir, "server-input", "path_traversal_hits.jsonl")},
		{category: "server-input", source: "server-input/file_inclusion_hits.jsonl", path: filepath.Join(fuzzDir, "server-input", "file_inclusion_hits.jsonl")},
		{category: "adv-injection", source: "adv-injection/xxe_hits.jsonl", path: filepath.Join(fuzzDir, "adv-injection", "xxe_hits.jsonl")},
		{category: "adv-injection", source: "adv-injection/soap_hits.jsonl", path: filepath.Join(fuzzDir, "adv-injection", "soap_hits.jsonl")},
		{category: "adv-injection", source: "adv-injection/ssrf_hits.jsonl", path: filepath.Join(fuzzDir, "adv-injection", "ssrf_hits.jsonl")},
		{category: "adv-injection", source: "adv-injection/smtp_hits.jsonl", path: filepath.Join(fuzzDir, "adv-injection", "smtp_hits.jsonl")},
		{category: "csrf", source: "csrf/findings.jsonl", path: filepath.Join(fuzzDir, "csrf", "findings.jsonl")},
		{category: "clickjacking", source: "clickjacking/findings.jsonl", path: filepath.Join(fuzzDir, "clickjacking", "findings.jsonl")},
		{category: "cors", source: "cors/findings.jsonl", path: filepath.Join(fuzzDir, "cors", "findings.jsonl")},
		{category: "open-redirect", source: "open-redirect/findings.jsonl", path: filepath.Join(fuzzDir, "open-redirect", "findings.jsonl")},
		{category: "nuclei", source: "nuclei/findings.jsonl", path: filepath.Join(fuzzDir, "nuclei", "findings.jsonl")},
		{category: "xss", source: "xss/reflected_hits.jsonl", path: filepath.Join(fuzzDir, "xss", "reflected_hits.jsonl")},
		{category: "xss", source: "xss/dom_hits.jsonl", path: filepath.Join(fuzzDir, "xss", "dom_hits.jsonl")},
		{category: "xss", source: "xss/stored_hits.jsonl", path: filepath.Join(fuzzDir, "xss", "stored_hits.jsonl")},
	}
	var leads []leadItem
	latest := time.Time{}
	for _, spec := range specs {
		rows, modTime := readJSONLRecords(spec.path)
		if modTime.After(latest) {
			latest = modTime
		}
		for _, row := range rows {
			lead := buildLeadItem(spec.category, spec.source, row, roots)
			if lead.ID == "" || lead.Domain == "" {
				continue
			}
			leads = append(leads, lead)
		}
	}
	dedup := make(map[string]leadItem, len(leads))
	for _, lead := range leads {
		if current, ok := dedup[lead.ID]; ok {
			if lead.ROI > current.ROI {
				dedup[lead.ID] = lead
			}
			continue
		}
		dedup[lead.ID] = lead
	}
	uniqueLeads := make([]leadItem, 0, len(dedup))
	states := s.snapshotLeadStates()
	for _, lead := range dedup {
		state := states[lead.ID]
		if state.Bucket == "deleted" {
			continue
		}
		lead.Done = state.Done
		lead.Bucket = state.Bucket
		uniqueLeads = append(uniqueLeads, lead)
	}
	sort.Slice(uniqueLeads, func(i, j int) bool {
		if uniqueLeads[i].ROI == uniqueLeads[j].ROI {
			return uniqueLeads[i].ID < uniqueLeads[j].ID
		}
		return uniqueLeads[i].ROI > uniqueLeads[j].ROI
	})
	return uniqueLeads, latest, nil
}

func buildWildcardGroups(leads []leadItem) []leadsWildcardGroup {
	wildcardBuckets := make(map[string]map[string][]leadItem)
	for _, lead := range leads {
		wc := lead.Wildcard
		if wc == "" {
			wc = "(unmapped)"
		}
		if wildcardBuckets[wc] == nil {
			wildcardBuckets[wc] = make(map[string][]leadItem)
		}
		wildcardBuckets[wc][lead.Domain] = append(wildcardBuckets[wc][lead.Domain], lead)
	}

	var wildcardGroups []leadsWildcardGroup
	for wildcard, domains := range wildcardBuckets {
		group := leadsWildcardGroup{Wildcard: wildcard}
		var domainGroups []leadsDomainGroup
		for domain, items := range domains {
			dg := leadsDomainGroup{
				Domain:    domain,
				Wildcard:  wildcard,
				Leads:     append([]leadItem{}, items...),
				LeadCount: len(items),
			}
			sort.Slice(dg.Leads, func(i, j int) bool {
				if dg.Leads[i].ROI == dg.Leads[j].ROI {
					return dg.Leads[i].ID < dg.Leads[j].ID
				}
				return dg.Leads[i].ROI > dg.Leads[j].ROI
			})
			for _, lead := range dg.Leads {
				dg.ROI += lead.ROI
				switch strings.ToLower(strings.TrimSpace(lead.Severity)) {
				case "high", "critical":
					dg.HighCount++
				case "medium":
					dg.MediumCount++
				default:
					dg.LowCount++
				}
			}
			domainGroups = append(domainGroups, dg)
		}
		sort.Slice(domainGroups, func(i, j int) bool {
			if domainGroups[i].ROI == domainGroups[j].ROI {
				return domainGroups[i].Domain < domainGroups[j].Domain
			}
			return domainGroups[i].ROI > domainGroups[j].ROI
		})
		group.Domains = domainGroups
		group.DomainCount = len(domainGroups)
		for _, dg := range domainGroups {
			group.ROI += dg.ROI
			group.LeadCount += dg.LeadCount
		}
		wildcardGroups = append(wildcardGroups, group)
	}
	sort.Slice(wildcardGroups, func(i, j int) bool {
		if wildcardGroups[i].ROI == wildcardGroups[j].ROI {
			return wildcardGroups[i].Wildcard < wildcardGroups[j].Wildcard
		}
		return wildcardGroups[i].ROI > wildcardGroups[j].ROI
	})
	return wildcardGroups
}

func normalizeLeadBucket(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "active":
		return "", true
	case "hits":
		return "hits", true
	case "investigation", "further-investigation", "further_investigation":
		return "investigation", true
	case "archive":
		return "archive", true
	case "deleted":
		return "deleted", true
	default:
		return "", false
	}
}

func (s *Server) loadLeadStates() {
	s.leadStateMu.Lock()
	defer s.leadStateMu.Unlock()
	s.leadStates = map[string]leadState{}
	raw, err := os.ReadFile(s.leadStatePath)
	if err != nil {
		return
	}
	var parsed map[string]leadState
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return
	}
	for id, state := range parsed {
		if strings.TrimSpace(id) == "" {
			continue
		}
		bucket, ok := normalizeLeadBucket(state.Bucket)
		if !ok {
			continue
		}
		state.Bucket = bucket
		s.leadStates[id] = state
	}
}

func (s *Server) saveLeadStatesLocked() error {
	if s.leadStatePath == "" {
		return errors.New("lead state path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(s.leadStatePath), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s.leadStates, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.leadStatePath, raw, 0o600)
}

func (s *Server) snapshotLeadStates() map[string]leadState {
	s.leadStateMu.Lock()
	defer s.leadStateMu.Unlock()
	out := make(map[string]leadState, len(s.leadStates))
	for id, state := range s.leadStates {
		out[id] = state
	}
	return out
}

func readBodySnippet(r io.Reader, limit int64) (string, error) {
	if r == nil {
		return "", nil
	}
	if limit <= 0 {
		limit = 2048
	}
	raw, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
