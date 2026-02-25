package configstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	configVersion = 1
	envKey        = "BFLOW_CONFIG_KEY"
	envGithubKeys = "BFLOW_GITHUB_KEYS"
	envGithubLabels = "BFLOW_GITHUB_KEY_LABELS"
	envGithubAutoRun = "BFLOW_GITHUB_AUTO_RUN"
)

type Store struct {
	path string
	key  []byte
	mu   sync.Mutex
}

type Config struct {
	Version   int                      `json:"version"`
	Providers map[string]*Provider     `json:"providers"`
}

type Provider struct {
	AutoRun bool        `json:"auto_run"`
	Keys    []KeyRecord `json:"keys"`
}

type KeyRecord struct {
	ID        string        `json:"id"`
	Label     string        `json:"label"`
	Active    bool          `json:"active"`
	Value     EncryptedValue `json:"value"`
	CreatedAt string        `json:"created_at"`
	UpdatedAt string        `json:"updated_at"`
	LastUsed  string        `json:"last_used,omitempty"`
	LastError string        `json:"last_error,omitempty"`
}

type EncryptedValue struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type DecryptedConfig struct {
	Version   int                               `json:"version"`
	Providers map[string]*DecryptedProvider      `json:"providers"`
}

type DecryptedProvider struct {
	AutoRun bool           `json:"auto_run"`
	Keys    []DecryptedKey `json:"keys"`
}

type DecryptedKey struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Active    bool   `json:"active"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	LastUsed  string `json:"last_used,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

func (p *DecryptedProvider) ActiveTokens() []DecryptedKey {
	var tokens []DecryptedKey
	for _, key := range p.Keys {
		if key.Active && strings.TrimSpace(key.Value) != "" {
			tokens = append(tokens, key)
		}
	}
	return tokens
}

func New(path string) (*Store, error) {
	key, err := loadKey()
	if err != nil {
		return nil, err
	}
	return &Store{path: path, key: key}, nil
}

func loadKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return nil, fmt.Errorf("%s is not set", envKey)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", envKey, err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", envKey, len(decoded))
	}
	return decoded, nil
}

func (s *Store) Load() (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (*Config, error) {
	if s.path == "" {
		return nil, errors.New("config path is empty")
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := defaultConfig()
			if err := s.applyPreload(cfg); err != nil {
				return nil, err
			}
			if err := s.saveLocked(cfg); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Providers == nil {
		cfg.Providers = map[string]*Provider{}
	}
	if cfg.Version == 0 {
		cfg.Version = configVersion
	}
	return &cfg, nil
}

func (s *Store) Save(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(cfg)
}

func (s *Store) saveLocked(cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	cfg.Version = configVersion
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

func defaultConfig() *Config {
	return &Config{
		Version:   configVersion,
		Providers: map[string]*Provider{},
	}
}

func (s *Store) applyPreload(cfg *Config) error {
	keysRaw := strings.TrimSpace(os.Getenv(envGithubKeys))
	if keysRaw == "" {
		return nil
	}
	labelsRaw := strings.TrimSpace(os.Getenv(envGithubLabels))
	var labels []string
	if labelsRaw != "" {
		for _, label := range strings.Split(labelsRaw, ",") {
			label = strings.TrimSpace(label)
			if label != "" {
				labels = append(labels, label)
			}
		}
	}

	autoRun := true
	if val := strings.TrimSpace(os.Getenv(envGithubAutoRun)); val != "" {
		autoRun = strings.EqualFold(val, "true") || val == "1" || strings.EqualFold(val, "yes")
	}

	provider := cfg.Providers["github"]
	if provider == nil {
		provider = &Provider{AutoRun: autoRun}
		cfg.Providers["github"] = provider
	} else {
		provider.AutoRun = autoRun
	}

	for idx, token := range strings.Split(keysRaw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		enc, err := s.encryptValue(token)
		if err != nil {
			return err
		}
		label := fmt.Sprintf("token-%d", idx+1)
		if idx < len(labels) && labels[idx] != "" {
			label = labels[idx]
		}
		provider.Keys = append(provider.Keys, KeyRecord{
			ID:        newID(),
			Label:     label,
			Active:    true,
			Value:     enc,
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
		})
	}
	return nil
}

func (s *Store) LoadDecrypted() (*DecryptedConfig, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}

	view := &DecryptedConfig{
		Version:   cfg.Version,
		Providers: map[string]*DecryptedProvider{},
	}

	for name, provider := range cfg.Providers {
		out := &DecryptedProvider{AutoRun: provider.AutoRun}
		for _, key := range provider.Keys {
			value, err := s.decryptValue(key.Value)
			if err != nil {
				return nil, err
			}
			out.Keys = append(out.Keys, DecryptedKey{
				ID:        key.ID,
				Label:     key.Label,
				Active:    key.Active,
				Value:     value,
				CreatedAt: key.CreatedAt,
				UpdatedAt: key.UpdatedAt,
				LastUsed:  key.LastUsed,
				LastError: key.LastError,
			})
		}
		view.Providers[name] = out
	}

	return view, nil
}

func (s *Store) UpsertKey(providerName string, key DecryptedKey) (*DecryptedKey, error) {
	cfg, err := s.Load()
	if err != nil {
		return nil, err
	}

	provider := cfg.Providers[providerName]
	if provider == nil {
		provider = &Provider{AutoRun: true}
		cfg.Providers[providerName] = provider
	}

	enc, err := s.encryptValue(key.Value)
	if err != nil {
		return nil, err
	}

	now := time.Now().Format(time.RFC3339)
	if key.ID == "" {
		key.ID = newID()
		key.CreatedAt = now
	}
	key.UpdatedAt = now

	found := false
	for idx := range provider.Keys {
		if provider.Keys[idx].ID == key.ID {
			provider.Keys[idx].Label = key.Label
			provider.Keys[idx].Active = key.Active
			provider.Keys[idx].Value = enc
			provider.Keys[idx].UpdatedAt = now
			found = true
			break
		}
	}
	if !found {
		provider.Keys = append(provider.Keys, KeyRecord{
			ID:        key.ID,
			Label:     key.Label,
			Active:    key.Active,
			Value:     enc,
			CreatedAt: key.CreatedAt,
			UpdatedAt: now,
			LastUsed:  key.LastUsed,
			LastError: key.LastError,
		})
	}

	if err := s.Save(cfg); err != nil {
		return nil, err
	}

	return &key, nil
}

func (s *Store) DeleteKey(providerName, keyID string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	provider := cfg.Providers[providerName]
	if provider == nil {
		return nil
	}
	var updated []KeyRecord
	for _, key := range provider.Keys {
		if key.ID == keyID {
			continue
		}
		updated = append(updated, key)
	}
	provider.Keys = updated
	return s.Save(cfg)
}

func (s *Store) UpdateProviderSettings(providerName string, autoRun bool) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	provider := cfg.Providers[providerName]
	if provider == nil {
		provider = &Provider{}
		cfg.Providers[providerName] = provider
	}
	provider.AutoRun = autoRun
	return s.Save(cfg)
}

func (s *Store) UpdateTokenUsage(providerName, keyID string, used time.Time, lastErr string) error {
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	provider := cfg.Providers[providerName]
	if provider == nil {
		return nil
	}
	for idx := range provider.Keys {
		if provider.Keys[idx].ID == keyID {
			provider.Keys[idx].LastUsed = used.Format(time.RFC3339)
			provider.Keys[idx].LastError = lastErr
			provider.Keys[idx].UpdatedAt = time.Now().Format(time.RFC3339)
			break
		}
	}
	return s.Save(cfg)
}

func (s *Store) encryptValue(value string) (EncryptedValue, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return EncryptedValue{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedValue{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedValue{}, err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), nil)
	return EncryptedValue{
		Version:    1,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (s *Store) decryptValue(enc EncryptedValue) (string, error) {
	if enc.Version != 1 {
		return "", fmt.Errorf("unsupported encrypted value version %d", enc.Version)
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func newID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
