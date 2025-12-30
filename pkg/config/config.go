package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config keeps all paths and options that used to live in flow.conf.
type Config struct {
	LogFile     string      `yaml:"log_file"`
	Lists       Lists       `yaml:"lists"`
	Paths       Paths       `yaml:"paths"`
	Wordlists   Wordlists   `yaml:"wordlists"`
	NmapSummary NmapSummary `yaml:"nmap_summary"`
}

// Lists is the collection of file references to scope lists.
type Lists struct {
	Organizations string `yaml:"organizations"`
	IPs           string `yaml:"ips"`
	Wildcards     string `yaml:"wildcards"`
	Domains       string `yaml:"domains"`
	APIDomains    string `yaml:"apidomains"`
	OutOfScope    string `yaml:"out_of_scope"`
}

// Paths holds working directories and auxiliary files.
type Paths struct {
	SitemapsFile     string `yaml:"sitemaps_file"`
	RobotsDir        string `yaml:"robots_dir"`
	RobotsHitsDir    string `yaml:"robots_hits_dir"`
	RobotsNoHitsDir  string `yaml:"robots_no_hits_dir"`
	DorkingDir       string `yaml:"dorking_dir"`
	FuzzingDir       string `yaml:"fuzzing_dir"`
	FFUFDir          string `yaml:"ffuf_dir"`
	FuzzingHitsDir   string `yaml:"fuzzing_hits_dir"`
	FuzzingNoHitsDir string `yaml:"fuzzing_no_hits_dir"`
	AllHitsFile      string `yaml:"all_hits_file"`
	LogsDir          string `yaml:"logs_dir"`
	NmapDir          string `yaml:"nmap_dir"`
}

// Wordlists references external wordlist files.
type Wordlists struct {
	APIWild501            string `yaml:"api_wild_501"`
	SecListAPILongest     string `yaml:"seclist_api_longest"`
	CustomProjectSpecific string `yaml:"custom_project_specific"`
	APIDocs               string `yaml:"apidocs"`
}

// NmapSummary controls the summary files and interesting targets.
type NmapSummary struct {
	Enable              bool     `yaml:"enable"`
	SummaryFile         string   `yaml:"summary_file"`
	PointersFile        string   `yaml:"pointers_file"`
	ServicesFile        string   `yaml:"services_file"`
	SearchsploitFile    string   `yaml:"searchsploit_results"`
	InterestingServices []string `yaml:"interesting_services"`
	InterestingPorts    []string `yaml:"interesting_ports"`
}

// Load reads a YAML configuration file and expands environment variables.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	cfg.expandPaths()
	return &cfg, nil
}

func (c *Config) expandPaths() {
	c.LogFile = expand(c.LogFile)

	c.Lists.Organizations = expand(c.Lists.Organizations)
	c.Lists.IPs = expand(c.Lists.IPs)
	c.Lists.Wildcards = expand(c.Lists.Wildcards)
	c.Lists.Domains = expand(c.Lists.Domains)
	c.Lists.APIDomains = expand(c.Lists.APIDomains)
	c.Lists.OutOfScope = expand(c.Lists.OutOfScope)

	c.Paths.SitemapsFile = expand(c.Paths.SitemapsFile)
	c.Paths.RobotsDir = expand(c.Paths.RobotsDir)
	c.Paths.RobotsHitsDir = expand(c.Paths.RobotsHitsDir)
	c.Paths.RobotsNoHitsDir = expand(c.Paths.RobotsNoHitsDir)
	c.Paths.DorkingDir = expand(c.Paths.DorkingDir)
	c.Paths.FuzzingDir = expand(c.Paths.FuzzingDir)
	c.Paths.FFUFDir = expand(c.Paths.FFUFDir)
	c.Paths.FuzzingHitsDir = expand(c.Paths.FuzzingHitsDir)
	c.Paths.FuzzingNoHitsDir = expand(c.Paths.FuzzingNoHitsDir)
	c.Paths.AllHitsFile = expand(c.Paths.AllHitsFile)
	c.Paths.LogsDir = expand(c.Paths.LogsDir)
	c.Paths.NmapDir = expand(c.Paths.NmapDir)

	c.Wordlists.APIWild501 = expand(c.Wordlists.APIWild501)
	c.Wordlists.SecListAPILongest = expand(c.Wordlists.SecListAPILongest)
	c.Wordlists.CustomProjectSpecific = expand(c.Wordlists.CustomProjectSpecific)
	c.Wordlists.APIDocs = expand(c.Wordlists.APIDocs)

	c.NmapSummary.SummaryFile = expand(c.NmapSummary.SummaryFile)
	c.NmapSummary.PointersFile = expand(c.NmapSummary.PointersFile)
	c.NmapSummary.ServicesFile = expand(c.NmapSummary.ServicesFile)
	c.NmapSummary.SearchsploitFile = expand(c.NmapSummary.SearchsploitFile)
}

func expand(path string) string {
	if path == "" {
		return path
	}

	path = os.ExpandEnv(path)

	if strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	return filepath.Clean(path)
}
