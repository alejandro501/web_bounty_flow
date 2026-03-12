package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rojo/hack/web_bounty_flow/pkg/configstore"
)

type flowToolsPayload struct {
	Tools map[string]bool `json:"tools"`
}

func (s *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.configStore == nil {
		http.Error(w, "config store not available (BFLOW_CONFIG_KEY missing)", http.StatusServiceUnavailable)
		return
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := configResponse{Version: cfg.Version, Providers: cfg.Providers}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) flowToolsConfigHandler(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil {
		http.Error(w, "config store not available (BFLOW_CONFIG_KEY missing)", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload flowToolsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	allowed := map[string]bool{
		"amass":       true,
		"sublist3r":   true,
		"assetfinder": true,
		"gau":         true,
		"ctl":         true,
		"subfinder":   true,
		"chaos":       true,
	}
	for provider, enabled := range payload.Tools {
		if !allowed[provider] {
			http.Error(w, "unsupported flow tool provider: "+provider, http.StatusBadRequest)
			return
		}
		if err := s.configStore.UpdateProviderSettings(provider, enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) networkHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enabled := s.loadTorEnabled()
		proxyEnabled, proxyHost, proxyPort := s.loadProxySettings()
		s.mu.Lock()
		probe := s.torProbe
		probeAt := s.torProbeAt
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkResponse{
			TorEnabled:   enabled,
			ProxyEnabled: proxyEnabled,
			ProxyHost:    proxyHost,
			ProxyPort:    proxyPort,
			ProbeMode:    probe.Mode,
			ProbeIP:      probe.IP,
			ProbeAt:      probeAt,
			ProbeError:   probe.Error,
			ProbeSrc:     probe.Source,
		})
		return
	case http.MethodPut:
		var payload networkPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		host := strings.TrimSpace(payload.ProxyHost)
		if host == "" {
			host = "localhost"
		}
		port := payload.ProxyPort
		if port == 0 {
			port = 8080
		}
		if port < 1 || port > 65535 {
			http.Error(w, "proxy_port must be between 1 and 65535", http.StatusBadRequest)
			return
		}
		s.torEnabled = payload.TorEnabled
		s.proxyEnabled = payload.ProxyEnabled
		s.proxyHost = host
		s.proxyPort = port
		if s.configStore != nil {
			if err := s.configStore.UpdateProviderSettings("network", payload.TorEnabled); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := s.saveProxySettings(payload.ProxyEnabled, host, port); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.applyNetworkSettingsToApp()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkResponse{
			TorEnabled:   payload.TorEnabled,
			ProxyEnabled: payload.ProxyEnabled,
			ProxyHost:    host,
			ProxyPort:    port,
		})
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) applyNetworkSettingsToApp() {
	if s.app == nil {
		return
	}
	s.app.SetTorEnabled(s.loadTorEnabled())
	proxyEnabled, host, port := s.loadProxySettings()
	s.app.SetProxy(proxyEnabled, host, port)
}

func (s *Server) loadProxySettings() (bool, string, int) {
	if s.configStore == nil {
		if strings.TrimSpace(s.proxyHost) == "" {
			s.proxyHost = "localhost"
		}
		if s.proxyPort <= 0 {
			s.proxyPort = 8080
		}
		return s.proxyEnabled, s.proxyHost, s.proxyPort
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		if strings.TrimSpace(s.proxyHost) == "" {
			s.proxyHost = "localhost"
		}
		if s.proxyPort <= 0 {
			s.proxyPort = 8080
		}
		return s.proxyEnabled, s.proxyHost, s.proxyPort
	}
	provider := cfg.Providers["proxy"]
	if provider == nil {
		if strings.TrimSpace(s.proxyHost) == "" {
			s.proxyHost = "localhost"
		}
		if s.proxyPort <= 0 {
			s.proxyPort = 8080
		}
		return s.proxyEnabled, s.proxyHost, s.proxyPort
	}
	host := "localhost"
	port := 8080
	if len(provider.Keys) > 0 {
		value := strings.TrimSpace(provider.Keys[0].Value)
		if value != "" {
			if parsedHost, parsedPort, ok := parseHostPortValue(value); ok {
				host = parsedHost
				port = parsedPort
			}
		}
	}
	s.proxyEnabled = provider.AutoRun
	s.proxyHost = host
	s.proxyPort = port
	return s.proxyEnabled, s.proxyHost, s.proxyPort
}

func (s *Server) saveProxySettings(enabled bool, host string, port int) error {
	if s.configStore == nil {
		return nil
	}
	if err := s.configStore.UpdateProviderSettings("proxy", enabled); err != nil {
		return err
	}
	cfg, err := s.configStore.LoadDecrypted()
	if err != nil {
		return err
	}
	keyID := ""
	if provider := cfg.Providers["proxy"]; provider != nil && len(provider.Keys) > 0 {
		keyID = provider.Keys[0].ID
	}
	_, err = s.configStore.UpsertKey("proxy", configstore.DecryptedKey{
		ID:     keyID,
		Label:  "default",
		Value:  fmt.Sprintf("%s:%d", host, port),
		Active: enabled,
	})
	return err
}

func parseHostPortValue(raw string) (string, int, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", 0, false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.ParseRequestURI(value)
		if err == nil && parsed != nil {
			host := strings.TrimSpace(parsed.Hostname())
			portStr := parsed.Port()
			if host == "" {
				return "", 0, false
			}
			if portStr == "" {
				return host, 8080, true
			}
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return "", 0, false
			}
			return host, port, true
		}
	}
	if strings.Contains(value, ":") {
		last := strings.LastIndex(value, ":")
		host := strings.TrimSpace(value[:last])
		portStr := strings.TrimSpace(value[last+1:])
		port, err := strconv.Atoi(portStr)
		if err != nil || host == "" || port < 1 || port > 65535 {
			return "", 0, false
		}
		return host, port, true
	}
	return value, 8080, true
}

func (s *Server) currentProxyURL() (bool, string) {
	enabled, host, port := s.loadProxySettings()
	if !enabled {
		return false, ""
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}
	if port <= 0 {
		port = 8080
	}
	return true, fmt.Sprintf("http://%s:%d", host, port)
}

func (s *Server) providerConfigHandler(w http.ResponseWriter, r *http.Request) {
	if s.configStore == nil {
		http.Error(w, "config store not available (BFLOW_CONFIG_KEY missing)", http.StatusServiceUnavailable)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/config/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}
	provider := parts[0]

	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		cfg, err := s.configStore.LoadDecrypted()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := cfg.Providers[provider]
		if out == nil {
			out = &configstore.DecryptedProvider{AutoRun: true}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	case len(parts) == 2 && parts[1] == "settings" && r.Method == http.MethodPut:
		var payload settingsPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.configStore.UpdateProviderSettings(provider, payload.AutoRun); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case len(parts) >= 2 && parts[1] == "keys":
		s.handleKeys(provider, parts[2:], w, r)
		return
	default:
		http.Error(w, "unsupported config route", http.StatusNotFound)
	}
}

func (s *Server) handleKeys(provider string, rest []string, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var payload keyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := configstore.DecryptedKey{
			Label:  payload.Label,
			Value:  payload.Value,
			Active: payload.Active,
		}
		updated, err := s.configStore.UpsertKey(provider, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodPut:
		if len(rest) == 0 || rest[0] == "" {
			http.Error(w, "key id required", http.StatusBadRequest)
			return
		}
		var payload keyPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := configstore.DecryptedKey{
			ID:     rest[0],
			Label:  payload.Label,
			Value:  payload.Value,
			Active: payload.Active,
		}
		updated, err := s.configStore.UpsertKey(provider, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodDelete:
		if len(rest) == 0 || rest[0] == "" {
			http.Error(w, "key id required", http.StatusBadRequest)
			return
		}
		if err := s.configStore.DeleteKey(provider, rest[0]); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) githubRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.app == nil {
		http.Error(w, "app not available", http.StatusServiceUnavailable)
		return
	}
	go func() {
		_ = s.app.RunGithubDorking(context.Background())
	}()
	w.WriteHeader(http.StatusAccepted)
}
