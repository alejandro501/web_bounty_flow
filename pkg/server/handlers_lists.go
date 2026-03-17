package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	list := r.FormValue("list_type")
	if list == "" {
		http.Error(w, "list_type is required", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	dest, err := s.listPath(list)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.saveTemporaryFile(dest, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(uploadResponse{Status: "uploaded"})
}

func (s *Server) urlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req urlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.ListType == "" || req.URL == "" {
		http.Error(w, "list_type and url are required", http.StatusBadRequest)
		return
	}

	dest, err := s.listPath(req.ListType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entry := strings.TrimSpace(req.URL)
	if entry == "" {
		http.Error(w, "url cannot be empty", http.StatusBadRequest)
		return
	}

	existing := readListLines(dest)
	for _, line := range existing {
		if strings.EqualFold(line, entry) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(urlResponse{
				Status:  "exists",
				Message: "Entry already exists",
			})
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	f, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, entry)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(urlResponse{
		Status:  "appended",
		Message: "Entry appended",
	})
}

func (s *Server) listHandler(w http.ResponseWriter, r *http.Request) {
	listType := r.URL.Query().Get("type")
	if listType == "" {
		http.Error(w, "type query parameter required", http.StatusBadRequest)
		return
	}

	dest, err := s.listPath(listType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		present := false
		if info, statErr := os.Stat(dest); statErr == nil && !info.IsDir() {
			present = true
		}
		lines := readListLines(dest)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"present": present,
			"entries": lines,
		})
	case http.MethodPut:
		var payload listPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(dest, []byte(payload.Content), 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		lines := readListLines(dest)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"present": true,
			"entries": lines,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) notesHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("name")))
	path, err := notePath(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		raw, readErr := os.ReadFile(path)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(notePayload{Content: string(raw)})
		return
	case http.MethodPut:
		var payload notePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(path, []byte(payload.Content), 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(notePayload{Content: payload.Content})
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func notePath(name string) (string, error) {
	switch name {
	case "notes":
		return filepath.Join("_notes", "notes.md"), nil
	case "manual_tips":
		return filepath.Join("_notes", "useful_manual_tips.md"), nil
	case "cookie":
		return filepath.Join("_notes", "cookie.md"), nil
	case "auth":
		return filepath.Join("_notes", "auth.md"), nil
	default:
		return "", fmt.Errorf("unsupported note name %q", name)
	}
}
