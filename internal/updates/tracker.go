package updates

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// markerName is dropped into rule-set directories to record the last download
// time. It's a regular file so users can inspect / cron-check it from outside.
const markerName = ".vanguard_updated"

// LastCheckPath returns the path to the global "last update check" marker —
// updated every time CheckAll runs, regardless of whether anything changed.
// Lives under config/ so it survives across cases.
func LastCheckPath(rootDir string) string {
	return filepath.Join(rootDir, "config", "last_update_check")
}

// ReadLastCheck returns the timestamp of the most recent update check, or
// the zero time when no check has run yet.
func ReadLastCheck(rootDir string) time.Time {
	data, err := os.ReadFile(LastCheckPath(rootDir))
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// WriteLastCheck records when CheckAll last ran.
func WriteLastCheck(rootDir string, t time.Time) error {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	path := LastCheckPath(rootDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(t.UTC().Format(time.RFC3339)), 0o644)
}

// MarkerPath returns the path to the timestamp marker for a rules directory.
func MarkerPath(rootDir, localPath string) string {
	return filepath.Join(rootDir, filepath.FromSlash(localPath), markerName)
}

// ReadTimestamp returns the recorded last-update time for a rules directory,
// or the zero value if no marker exists.
func ReadTimestamp(rootDir, localPath string) time.Time {
	data, err := os.ReadFile(MarkerPath(rootDir, localPath))
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// WriteTimestamp records the current time as the rule set's last-update.
// Best-effort: errors are returned to the caller for logging but the rule
// install itself isn't rolled back if writing the marker fails.
func WriteTimestamp(rootDir, localPath string, t time.Time) error {
	if t.IsZero() {
		t = time.Now().UTC()
	}
	path := MarkerPath(rootDir, localPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(t.UTC().Format(time.RFC3339)), 0o644)
}

// FormatAge returns a friendly "N days ago" string for a marker time, or
// "Never" when t is zero.
func FormatAge(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	dur := time.Since(t)
	switch {
	case dur < time.Minute:
		return "just now"
	case dur < time.Hour:
		return formatN(int(dur.Minutes()), "minute") + " ago"
	case dur < 24*time.Hour:
		return formatN(int(dur.Hours()), "hour") + " ago"
	}
	days := int(dur.Hours() / 24)
	return formatN(days, "day") + " ago"
}

func formatN(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return itoa(n) + " " + unit + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
