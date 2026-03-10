package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rojo/hack/web_bounty_flow/pkg/configstore"
)

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

func (s *Server) networkHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enabled := s.loadTorEnabled()
		s.mu.Lock()
		probe := s.torProbe
		probeAt := s.torProbeAt
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkResponse{
			TorEnabled: enabled,
			ProbeMode:  probe.Mode,
			ProbeIP:    probe.IP,
			ProbeAt:    probeAt,
			ProbeError: probe.Error,
			ProbeSrc:   probe.Source,
		})
		return
	case http.MethodPut:
		var payload networkPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.torEnabled = payload.TorEnabled
		if s.configStore != nil {
			if err := s.configStore.UpdateProviderSettings("network", payload.TorEnabled); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if s.app != nil {
			s.app.SetTorEnabled(payload.TorEnabled)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkResponse{TorEnabled: payload.TorEnabled})
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
