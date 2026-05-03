package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	logFileName    = "vanguard.log"
	maxLogFileSize = 10 * 1024 * 1024 // 10MB
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = [...]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

func (l LogLevel) String() string {
	if l >= DEBUG && l <= FATAL {
		return levelNames[l]
	}
	return fmt.Sprintf("LEVEL(%d)", l)
}

// ParseLevel converts a string to a LogLevel. Defaults to INFO for unrecognised input.
func ParseLevel(s string) LogLevel {
	switch s {
	case "DEBUG", "debug":
		return DEBUG
	case "INFO", "info":
		return INFO
	case "WARN", "warn":
		return WARN
	case "ERROR", "error":
		return ERROR
	case "FATAL", "fatal":
		return FATAL
	default:
		return INFO
	}
}

type Logger struct {
	mu       sync.Mutex
	level    LogLevel
	file     *os.File
	logDir   string
	logPath  string
	written  int64
	fileOnly bool
}

// NewLogger creates a logger that writes to both stderr and a file in logDir.
func NewLogger(logDir string, level LogLevel) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating log directory %s: %w", logDir, err)
	}

	logPath := filepath.Join(logDir, logFileName)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", logPath, err)
	}

	// Track current file size so rotation triggers correctly on restart.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log file %s: %w", logPath, err)
	}

	return &Logger{
		level:   level,
		file:    f,
		logDir:  logDir,
		logPath: logPath,
		written: info.Size(),
	}, nil
}

// SetFileOnly controls whether log output goes only to the file (true) or to
// both stderr and the file (false). Enable this while bubbletea owns the terminal.
func (l *Logger) SetFileOnly(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileOnly = enabled
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *Logger) Debug(component, message string, args ...interface{}) {
	l.log(DEBUG, component, message, args...)
}

func (l *Logger) Info(component, message string, args ...interface{}) {
	l.log(INFO, component, message, args...)
}

func (l *Logger) Warn(component, message string, args ...interface{}) {
	l.log(WARN, component, message, args...)
}

func (l *Logger) Error(component, message string, args ...interface{}) {
	l.log(ERROR, component, message, args...)
}

func (l *Logger) Fatal(component, message string, args ...interface{}) {
	l.log(FATAL, component, message, args...)
	os.Exit(1)
}

func (l *Logger) log(level LogLevel, component, message string, args ...interface{}) {
	if level < l.level {
		return
	}

	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}

	// Defence in depth: redact common credential patterns before persisting.
	// Callers should also avoid building log messages that include secrets in
	// the first place — this is the catch-net.
	message = sanitizeLogMessage(message)

	line := fmt.Sprintf("[%s] [%-5s] [%s] %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		level,
		component,
		message,
	)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to stderr unless TUI owns the terminal.
	if !l.fileOnly {
		fmt.Fprint(os.Stderr, line)
	}

	// Rotate if needed before writing.
	if l.written >= maxLogFileSize {
		l.rotate()
	}

	n, err := fmt.Fprint(l.file, line)
	if err == nil {
		l.written += int64(n)
	}
}

// sensitivePatterns matches the common ways tools expose credentials and
// secrets in command lines, env-var-style strings, HTTP headers, and config
// snippets that may surface in logs. Compiled once.
//
// Each pattern captures a "prefix" group (e.g. "password=", "-p ", "Bearer ")
// so the redactor can preserve the prefix and only mask the value — that
// keeps the log line readable for debugging while hiding the secret. Patterns
// are deliberately broad: false positives (a legitimate value containing the
// word "secret") are far cheaper than a leaked credential.
// Pattern ORDER MATTERS: more specific patterns run first so they can claim
// their match before a broader pattern fires. In particular, `bearer\s+` runs
// before `authorization` because "Authorization: Bearer <jwt>" needs to mask
// the JWT, not the literal "Bearer" token.
var sensitivePatterns = []*regexp.Regexp{
	// HTTP auth: "Authorization: Bearer <jwt>" — claim the whole header so
	// the broader "authorization=value" pattern doesn't redact only "Bearer".
	regexp.MustCompile(`(?i)(authorization\s*[=:]\s*bearer\s+)\S+`),
	// HTTP auth header value (standalone "Bearer <token>").
	regexp.MustCompile(`(?i)(bearer\s+)\S+`),
	// --flag value / -flag value — capture the flag + leading whitespace
	regexp.MustCompile(`(?i)(-p\s+)\S+`),                // psexec / mysql -p
	regexp.MustCompile(`(?i)(-P\s+)\S+`),                // some tools
	regexp.MustCompile(`(?i)(-pw\s+)\S+`),               // plink
	regexp.MustCompile(`(?i)(--password\s+)\S+`),
	regexp.MustCompile(`(?i)(-password\s+)\S+`),
	// key=value / key: value
	regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(passwd\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(token\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(secret\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(credential\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(authorization\s*[=:]\s*)\S+`),
	// Environment variable form (X=value with no leading dash)
	regexp.MustCompile(`(?i)(SSHPASS=)\S+`),
	regexp.MustCompile(`(?i)(VANGUARD_GITHUB_TOKEN=)\S+`),
	// GitHub PAT pattern (ghp_/gho_/ghu_/ghs_/ghr_ prefix)
	regexp.MustCompile(`(?i)(token\s+)gh[pousr]_\S+`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{16,}`),
	// Windows net use / share auth
	regexp.MustCompile(`(?i)(/user:\S+\s+)\S+`),
	// PowerShell inline plaintext-to-secure conversion
	regexp.MustCompile(`(?i)(ConvertTo-SecureString\s+)'[^']*'`),
}

// sanitizeLogMessage redacts credential / secret substrings before they hit
// disk or stderr.
//
// For patterns that capture a prefix group, the redacted output keeps the
// prefix verbatim and replaces only the value: "password=hunter2" becomes
// "password=[REDACTED]". For patterns without a capture group, the entire
// match is replaced with "[REDACTED]".
func sanitizeLogMessage(msg string) string {
	out := msg
	for _, re := range sensitivePatterns {
		out = re.ReplaceAllStringFunc(out, func(match string) string {
			subs := re.FindStringSubmatch(match)
			if len(subs) >= 2 && subs[1] != "" {
				return subs[1] + "[REDACTED]"
			}
			return "[REDACTED]"
		})
	}
	return out
}

// SanitizeCommandLog returns a short, redacted form of an exec.Command line
// suitable for logging from network/remote transports. Callers should NEVER
// log the full argv directly — pass it through here first.
//
// Format: "<binary> [N args]" plus any matched secrets are stripped out.
// The component logger then runs sanitizeLogMessage as the catch-net.
func SanitizeCommandLog(bin string, args []string) string {
	return fmt.Sprintf("%s [%d args, secrets redacted]",
		filepath.Base(bin), len(args))
}

// SanitizeRemoteOpLog returns a fixed log line for remote-operation kickoff
// that names the host and protocol but never includes the actual command —
// the command itself often embeds user-supplied IOC values, hostnames, or
// credentials we don't want persisted.
func SanitizeRemoteOpLog(host, protocol string) string {
	if host == "" {
		host = "<unknown>"
	}
	if protocol == "" {
		protocol = "<unknown>"
	}
	return fmt.Sprintf("Executing remote command on %s via %s",
		strings.TrimSpace(host), strings.TrimSpace(protocol))
}

// SanitizeLogMessage exposes the redaction filter for callers that build
// formatted strings outside the logger (e.g. error messages destined for the
// TUI that may also be logged later).
func SanitizeLogMessage(msg string) string {
	return sanitizeLogMessage(msg)
}

// rotate renames the current log to vanguard.log.1 and opens a fresh file.
// Must be called with l.mu held.
func (l *Logger) rotate() {
	l.file.Close()

	backupPath := l.logPath + ".1"
	// Remove old backup, ignore errors (may not exist).
	os.Remove(backupPath)
	os.Rename(l.logPath, backupPath)

	f, err := os.OpenFile(l.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		// If rotation fails, try to reopen in append mode as fallback.
		f, _ = os.OpenFile(l.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}

	l.file = f
	l.written = 0
}
