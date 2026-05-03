package security

import "testing"

func TestSanitizeShellArg(t *testing.T) {
	// Each pair: (input, expected). The transformation strips shell
	// metacharacters and NUL — anything else passes through.
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"foo bar", "foo bar"},
		{"a;rm -rf /", "arm -rf /"},
		{"`whoami`", "whoami"},
		{"$(id)", "id"},
		{"a|b&c", "abc"},
		{"line\nbreak", "linebreak"},
		{"with\x00null", "withnull"},
		{"safe-name_1.2.3", "safe-name_1.2.3"},
	}
	for _, c := range cases {
		got := SanitizeShellArg(c.in)
		if got != c.want {
			t.Errorf("SanitizeShellArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeIPAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.1", "192.168.1.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"not-an-ip", ""},
		{"192.168.1.1; rm -rf /", ""},
		{"192.168.1", ""},
	}
	for _, c := range cases {
		if got := SanitizeIPAddress(c.in); got != c.want {
			t.Errorf("SanitizeIPAddress(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeHostname(t *testing.T) {
	cases := []struct{ in, want string }{
		{"webserver-01", "webserver-01"},
		{"db.internal.example.com", "db.internal.example.com"},
		{"DC01_PROD", "DC01_PROD"},
		{"host;evil", ""},
		{"host with space", ""},
	}
	for _, c := range cases {
		if got := SanitizeHostname(c.in); got != c.want {
			t.Errorf("SanitizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeHash(t *testing.T) {
	cases := []struct{ in, want string }{
		{"d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"},
		{"DEADBEEF", "DEADBEEF"},
		{"not-hex", ""},
		{"abc; rm -rf /", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeHash(c.in); got != c.want {
			t.Errorf("SanitizeHash(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"evil.example.com", "evil.example.com"},
		{"sub.domain.co.uk", "sub.domain.co.uk"},
		{"no-tld", ""},
		{"with;injection.com", ""},
	}
	for _, c := range cases {
		if got := SanitizeDomain(c.in); got != c.want {
			t.Errorf("SanitizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeFileExtension(t *testing.T) {
	cases := []struct{ in, want string }{
		{"log", "log"},
		{".evtx", ".evtx"},
		{"exe; rm", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeFileExtension(c.in); got != c.want {
			t.Errorf("SanitizeFileExtension(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeDateTime(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-05-01", "2026-05-01"},
		{"2026-05-01 14:30", "2026-05-01 14:30"},
		{"2026-05-01; whoami", ""},
		{"yesterday", ""},
	}
	for _, c := range cases {
		if got := SanitizeDateTime(c.in); got != c.want {
			t.Errorf("SanitizeDateTime(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeFilePath(t *testing.T) {
	// SanitizeFilePath is permissive — it strips dangerous characters but
	// preserves legal path bits.
	cases := []struct{ in, want string }{
		{`C:\Windows\Temp\file.txt`, `C:\Windows\Temp\file.txt`},
		{"/etc/passwd", "/etc/passwd"},
		{"path with spaces.log", "path with spaces.log"},
		{"path;rm -rf /", "pathrm -rf /"},
		{"`evil`", "evil"},
	}
	for _, c := range cases {
		if got := SanitizeFilePath(c.in); got != c.want {
			t.Errorf("SanitizeFilePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
