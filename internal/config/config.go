package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	VanGuard     VanGuardConfig     `yaml:"vanguard"`
	Paths        PathsConfig        `yaml:"paths"`
	Network      NetworkConfig      `yaml:"network"`
	Velociraptor VelociraptorConfig `yaml:"velociraptor"`
	Memory       MemoryConfig       `yaml:"memory"`
	Disk         DiskConfig         `yaml:"disk"`
	Triage       TriageConfig       `yaml:"triage"`
	Updates      UpdatesConfig      `yaml:"updates"`
	Output       OutputConfig       `yaml:"output"`
	GitHub       GitHubConfig       `yaml:"github"`
}

// GitHubConfig carries optional GitHub API credentials. A personal access
// token (no special scopes — public-repo access only) raises the unauthenticated
// 60 req/hr ceiling to 5,000 req/hr, which matters when downloading the full
// tool catalog or running update checks.
//
// Token resolution order: VANGUARD_GITHUB_TOKEN env var first, then config.
type GitHubConfig struct {
	Token string `yaml:"token"`
}

type VanGuardConfig struct {
	Version      string `yaml:"version"`
	Analyst      string `yaml:"analyst"`
	Organization string `yaml:"organization"`
	LogLevel     string `yaml:"log_level"`
}

type PathsConfig struct {
	Output string            `yaml:"output"`
	Cases  string            `yaml:"cases"`
	Logs   string            `yaml:"logs"`
	Tools  map[string]string `yaml:"tools"`
	Rules  map[string]string `yaml:"rules"`
}

type NetworkConfig struct {
	DefaultMode string       `yaml:"default_mode"`
	SSH         SSHConfig    `yaml:"ssh"`
	WinRM       WinRMConfig  `yaml:"winrm"`
	PSExec      PSExecConfig `yaml:"psexec"`
}

type SSHConfig struct {
	Port    int    `yaml:"port"`
	KeyPath string `yaml:"key_path"`
	Timeout int    `yaml:"timeout"`
}

type WinRMConfig struct {
	Port    int  `yaml:"port"`
	SSLPort int  `yaml:"ssl_port"`
	UseSSL  bool `yaml:"use_ssl"`
	Timeout int  `yaml:"timeout"`
}

type PSExecConfig struct {
	CopyBinary bool `yaml:"copy_binary"`
	Cleanup    bool `yaml:"cleanup"`
}

type VelociraptorConfig struct {
	AutoDownload bool                    `yaml:"auto_download"`
	Server       VelociraptorServerConfig `yaml:"server"`
	Client       VelociraptorClientConfig `yaml:"client"`
}

type VelociraptorServerConfig struct {
	BindAddress   string `yaml:"bind_address"`
	FrontendPort  int    `yaml:"frontend_port"`
	GUIPort       int    `yaml:"gui_port"`
	Datastore     string `yaml:"datastore"`
	DatastorePath string `yaml:"datastore_path"`
}

type VelociraptorClientConfig struct {
	PollInterval int `yaml:"poll_interval"`
}

type MemoryConfig struct {
	CaptureToolWindows string           `yaml:"capture_tool_windows"`
	CaptureToolLinux   string           `yaml:"capture_tool_linux"`
	Volatility         VolatilityConfig `yaml:"volatility"`
}

type VolatilityConfig struct {
	SymbolsPath       string   `yaml:"symbols_path"`
	AutoDetectProfile bool     `yaml:"auto_detect_profile"`
	DefaultPlugins    []string `yaml:"default_plugins"`
}

type DiskConfig struct {
	KAPE KAPEConfig `yaml:"kape"`
	UAC  UACConfig  `yaml:"uac"`
}

type KAPEConfig struct {
	DefaultTargets []string `yaml:"default_targets"`
	DefaultModules []string `yaml:"default_modules"`
}

type UACConfig struct {
	Profile string `yaml:"profile"`
}

type TriageConfig struct {
	Hayabusa HayabusaConfig `yaml:"hayabusa"`
	Loki     LokiConfig     `yaml:"loki"`
}

type HayabusaConfig struct {
	MinLevel     string `yaml:"min_level"`
	OutputFormat string `yaml:"output_format"`
}

type LokiConfig struct {
	IntenseMode   bool `yaml:"intense_mode"`
	ScanProcesses bool `yaml:"scan_processes"`
	ScanFiles     bool `yaml:"scan_files"`
}

type UpdatesConfig struct {
	AutoCheck          bool `yaml:"auto_check"`
	CheckIntervalHours int  `yaml:"check_interval_hours"`
	AutoApply          bool `yaml:"auto_apply"`
}

type OutputConfig struct {
	DefaultFormat      string `yaml:"default_format"`
	IncludeTimestamps  bool   `yaml:"include_timestamps"`
	CompressLargeFiles bool   `yaml:"compress_large_files"`
	LargeFileThresholdMB int  `yaml:"large_file_threshold_mb"`
}

// Load reads a YAML config file, unmarshals it, and applies defaults for any zero values.
//
// Strict mode: yaml.v3's decoder is configured with KnownFields(true), so an
// unexpected key in vanguard.yaml fails the load with a clear error pointing
// at the offending field. Operators get immediate feedback for typos rather
// than silent ignoring of misspelled options.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytesReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// bytesReader is a tiny wrapper so we can use yaml.NewDecoder without pulling
// in bytes.NewReader at every call site.
func bytesReader(b []byte) *strings.Reader {
	return strings.NewReader(string(b))
}

// Save writes the config back to the given YAML file path.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	return nil
}

// applyDefaults fills in sensible defaults for any zero-valued fields.
func (c *Config) applyDefaults() {
	if c.VanGuard.LogLevel == "" {
		c.VanGuard.LogLevel = "info"
	}

	// Paths
	if c.Paths.Output == "" {
		c.Paths.Output = "./output"
	}
	if c.Paths.Cases == "" {
		c.Paths.Cases = "./cases"
	}
	if c.Paths.Logs == "" {
		c.Paths.Logs = "./logs"
	}
	if c.Paths.Tools == nil {
		c.Paths.Tools = map[string]string{
			"windows": "./bin/windows",
			"linux":   "./bin/linux",
		}
	}
	if c.Paths.Rules == nil {
		c.Paths.Rules = map[string]string{
			"sigma":    "./rules/sigma",
			"yara":     "./rules/yara",
			"hayabusa": "./rules/hayabusa/rules",
		}
	}

	// Network
	if c.Network.DefaultMode == "" {
		c.Network.DefaultMode = "local"
	}
	if c.Network.SSH.Port == 0 {
		c.Network.SSH.Port = 22
	}
	if c.Network.SSH.Timeout == 0 {
		c.Network.SSH.Timeout = 30
	}
	if c.Network.WinRM.Port == 0 {
		c.Network.WinRM.Port = 5985
	}
	if c.Network.WinRM.SSLPort == 0 {
		c.Network.WinRM.SSLPort = 5986
	}
	if c.Network.WinRM.Timeout == 0 {
		c.Network.WinRM.Timeout = 30
	}
	if !c.Network.PSExec.Cleanup {
		c.Network.PSExec.Cleanup = true
	}

	// Velociraptor
	if c.Velociraptor.Server.BindAddress == "" {
		c.Velociraptor.Server.BindAddress = "0.0.0.0"
	}
	if c.Velociraptor.Server.FrontendPort == 0 {
		c.Velociraptor.Server.FrontendPort = 8000
	}
	if c.Velociraptor.Server.GUIPort == 0 {
		c.Velociraptor.Server.GUIPort = 8889
	}
	if c.Velociraptor.Server.Datastore == "" {
		c.Velociraptor.Server.Datastore = "file"
	}
	if c.Velociraptor.Server.DatastorePath == "" {
		c.Velociraptor.Server.DatastorePath = "./velociraptor/datastore"
	}
	if c.Velociraptor.Client.PollInterval == 0 {
		c.Velociraptor.Client.PollInterval = 10
	}

	// Memory
	if c.Memory.CaptureToolWindows == "" {
		c.Memory.CaptureToolWindows = "winpmem"
	}
	if c.Memory.CaptureToolLinux == "" {
		c.Memory.CaptureToolLinux = "avml"
	}
	if c.Memory.Volatility.SymbolsPath == "" {
		c.Memory.Volatility.SymbolsPath = "./lib/volatility3/symbols"
	}
	if !c.Memory.Volatility.AutoDetectProfile {
		c.Memory.Volatility.AutoDetectProfile = true
	}
	if c.Memory.Volatility.DefaultPlugins == nil {
		c.Memory.Volatility.DefaultPlugins = []string{
			"windows.pslist.PsList",
			"windows.netscan.NetScan",
			"windows.malfind.Malfind",
		}
	}

	// Disk
	if c.Disk.KAPE.DefaultTargets == nil {
		c.Disk.KAPE.DefaultTargets = []string{"EventLogs", "Registry", "FileSystem"}
	}
	if c.Disk.KAPE.DefaultModules == nil {
		c.Disk.KAPE.DefaultModules = []string{"!EZParser"}
	}
	if c.Disk.UAC.Profile == "" {
		c.Disk.UAC.Profile = "full"
	}

	// Triage
	if c.Triage.Hayabusa.MinLevel == "" {
		c.Triage.Hayabusa.MinLevel = "medium"
	}
	if c.Triage.Hayabusa.OutputFormat == "" {
		c.Triage.Hayabusa.OutputFormat = "csv"
	}
	if !c.Triage.Loki.ScanProcesses {
		c.Triage.Loki.ScanProcesses = true
	}
	if !c.Triage.Loki.ScanFiles {
		c.Triage.Loki.ScanFiles = true
	}

	// Updates
	if c.Updates.CheckIntervalHours == 0 {
		c.Updates.CheckIntervalHours = 24
	}

	// Output
	if c.Output.DefaultFormat == "" {
		c.Output.DefaultFormat = "auto"
	}
	if !c.Output.IncludeTimestamps {
		c.Output.IncludeTimestamps = true
	}
	if c.Output.LargeFileThresholdMB == 0 {
		c.Output.LargeFileThresholdMB = 100
	}
}

// ToolPath returns the full path to a tool binary for the given platform.
func (c *Config) ToolPath(platform, tool string) string {
	base, ok := c.Paths.Tools[platform]
	if !ok {
		base = c.Paths.Tools[runtime.GOOS]
	}
	return filepath.Join(base, tool)
}

// Validate checks that the loaded config is well-formed: required paths
// exist (or can be created), port ranges are valid, network mode is one of
// the supported values, and operator-supplied paths don't try to escape the
// VanGuard root via "..". Returns an error listing every problem found, not
// just the first.
func (c *Config) Validate() error {
	dirs := []string{
		c.Paths.Output,
		c.Paths.Cases,
		c.Paths.Logs,
	}

	for _, dir := range dirs {
		if err := ensureDir(dir); err != nil {
			return fmt.Errorf("ensuring directory %s: %w", dir, err)
		}
	}

	var errs []string

	// Network ports — must fit a uint16.
	if !validPort(c.Network.SSH.Port) {
		errs = append(errs, fmt.Sprintf("invalid SSH port: %d", c.Network.SSH.Port))
	}
	if !validPort(c.Network.WinRM.Port) {
		errs = append(errs, fmt.Sprintf("invalid WinRM port: %d", c.Network.WinRM.Port))
	}
	if !validPort(c.Network.WinRM.SSLPort) {
		errs = append(errs, fmt.Sprintf("invalid WinRM SSL port: %d", c.Network.WinRM.SSLPort))
	}
	if !validPort(c.Velociraptor.Server.GUIPort) {
		errs = append(errs, fmt.Sprintf("invalid Velociraptor GUI port: %d", c.Velociraptor.Server.GUIPort))
	}
	if !validPort(c.Velociraptor.Server.FrontendPort) {
		errs = append(errs, fmt.Sprintf("invalid Velociraptor frontend port: %d", c.Velociraptor.Server.FrontendPort))
	}

	// Timeouts — sane bounds keep a misconfigured 10000s timeout from
	// freezing the TUI on a hung WinRM call.
	if !validTimeout(c.Network.SSH.Timeout) {
		errs = append(errs, fmt.Sprintf("invalid SSH timeout: %d (must be 1-3600)", c.Network.SSH.Timeout))
	}
	if !validTimeout(c.Network.WinRM.Timeout) {
		errs = append(errs, fmt.Sprintf("invalid WinRM timeout: %d (must be 1-3600)", c.Network.WinRM.Timeout))
	}

	// Network mode allow-list. Empty mode is replaced by the default in
	// applyDefaults(), so we only need to check the populated set.
	validModes := map[string]bool{
		"local": true, "remote-ssh": true, "remote-winrm": true,
		"remote-psexec": true, "server": true, "agent": true,
	}
	if !validModes[c.Network.DefaultMode] {
		errs = append(errs, fmt.Sprintf(
			"invalid network mode: %q (must be one of local / remote-ssh / remote-winrm / remote-psexec / server / agent)",
			c.Network.DefaultMode))
	}

	// Velociraptor bind address must be a valid IP (not a hostname), because
	// it is interpolated directly into the --merge JSON fragment passed to
	// `velociraptor config generate`. An invalid value here would silently
	// produce malformed JSON (or allow JSON injection before Fix 9).
	if addr := c.Velociraptor.Server.BindAddress; addr != "" && net.ParseIP(addr) == nil {
		errs = append(errs, fmt.Sprintf(
			"velociraptor.server.bind_address is not a valid IP address: %q", addr))
	}

	// Path-traversal check: operator-controlled paths must not contain "..".
	// Without this, a tampered vanguard.yaml could redirect output writes
	// anywhere on disk. We don't ban absolute paths because they're a
	// legitimate way to point output at a different drive.
	pathFields := map[string]string{
		"paths.output":                     c.Paths.Output,
		"paths.cases":                      c.Paths.Cases,
		"paths.logs":                       c.Paths.Logs,
		"velociraptor.server.datastore_path": c.Velociraptor.Server.DatastorePath,
		"memory.volatility.symbols_path":   c.Memory.Volatility.SymbolsPath,
	}
	for name, p := range pathFields {
		if strings.Contains(p, "..") {
			errs = append(errs, fmt.Sprintf("path %s contains '..': %s", name, p))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// validPort reports whether p is a valid TCP/UDP port number.
func validPort(p int) bool {
	return p >= 1 && p <= 65535
}

// validTimeout reports whether t is a sane timeout value in seconds.
// 1 second is the floor; 1 hour is the ceiling — anything longer is almost
// certainly a misconfiguration.
func validTimeout(t int) bool {
	return t >= 1 && t <= 3600
}

// ensureDir creates a directory if it doesn't already exist.
func ensureDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("checking %s: %w", path, err)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	return nil
}
