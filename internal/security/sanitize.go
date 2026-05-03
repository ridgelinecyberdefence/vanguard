// Package security provides input-sanitisation helpers used wherever
// user-supplied strings cross into a shell, command-line, or log surface.
//
// Two layers of defence apply across VanGuard:
//
//  1. Avoid shell interpolation entirely — prefer exec.Command(name, args...)
//     over exec.Command("sh", "-c", concat(...)). Where shell wrappers are
//     unavoidable (PowerShell, sh -c), apply type-specific sanitisation here
//     before the value reaches the shell.
//  2. Validate / strip dangerous characters at every boundary, even when the
//     consumer "should" be safe — depth in defence, not depth in trust.
//
// The validators (SanitizeIPAddress, SanitizeHostname, SanitizeHash,
// SanitizeDomain, SanitizeFileExtension) are strict: they return "" when the
// input doesn't match the expected shape so callers can detect rejection
// rather than silently passing a malformed value.
//
// SanitizeShellArg and SanitizeFilePath are permissive — they strip dangerous
// metacharacters but preserve the rest of the input. Use them only when the
// strict validators don't fit (free-form text, paths with spaces, etc.).
package security

import (
	"regexp"
	"strings"
)

// shellMetachars are characters that have special meaning in PowerShell or
// /bin/sh. Removed by SanitizeShellArg as a defence-in-depth measure when
// inserting a value into a command line that ultimately runs through a shell.
var shellMetachars = []string{";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "#", "\n", "\r", "'", "\""}

// SanitizeShellArg removes characters that could be used for command injection
// when an arg is interpolated into a shell command line. NOT a substitute for
// avoiding shell interpolation in the first place.
//
// Always strips: NUL byte, ; & | ` $ ( ) { } < > ! # CR LF
// Preserves: alphanumerics, spaces, ASCII punctuation that's shell-safe
// (- _ . / \ : @ , =), and the rest of the input.
func SanitizeShellArg(input string) string {
	input = strings.ReplaceAll(input, "\x00", "")
	for _, c := range shellMetachars {
		input = strings.ReplaceAll(input, c, "")
	}
	return input
}

// pathAllowedRe matches characters allowed in a sanitized file path:
// alphanumerics, both path separators, dots, hyphens, underscores, spaces,
// and the drive-letter colon (Windows). Anything else is stripped.
var pathAllowedRe = regexp.MustCompile(`[^a-zA-Z0-9\\/\.\-_ :]`)

// SanitizeFilePath removes characters that don't belong in a filesystem path,
// preserving Windows drive letters (e.g. C:) and both path separators.
// Returns the cleaned path; never returns "" for a non-empty input unless
// every character was disallowed.
func SanitizeFilePath(input string) string {
	return pathAllowedRe.ReplaceAllString(input, "")
}

// fileExtRe matches a file extension: optional leading dot, then 1+ alphanumerics.
var fileExtRe = regexp.MustCompile(`^\.?[a-zA-Z0-9]+$`)

// SanitizeFileExtension validates a file extension. Returns the input
// unchanged when valid, or "" when malformed. Accepts ".log", "log", "evtx".
func SanitizeFileExtension(input string) string {
	if fileExtRe.MatchString(input) {
		return input
	}
	return ""
}

// ipv4Re matches an IPv4 address (loose — does not bound octets to 0-255).
// Strict per-octet validation should layer on top of this when needed.
var ipv4Re = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// SanitizeIPAddress validates IPv4 format. Returns input on match, "" otherwise.
func SanitizeIPAddress(input string) string {
	if ipv4Re.MatchString(input) {
		return input
	}
	return ""
}

// hostnameRe matches a hostname or FQDN: alphanumerics, dots, hyphens.
// (Underscores are not RFC-valid in DNS but appear in Windows NetBIOS names —
// allowing them broadens applicability for IR scenarios.)
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9\.\-_]+$`)

// SanitizeHostname validates a hostname / FQDN. Returns input on match,
// "" otherwise.
func SanitizeHostname(input string) string {
	if hostnameRe.MatchString(input) {
		return input
	}
	return ""
}

// hexHashRe matches any hex string (suitable for MD5 / SHA1 / SHA256 / SHA512).
var hexHashRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)

// SanitizeHash validates a hex hash (any length). Returns input on match,
// "" otherwise. Caller may want to additionally check len() == 32/40/64/128.
func SanitizeHash(input string) string {
	if hexHashRe.MatchString(input) {
		return input
	}
	return ""
}

// domainRe matches a domain name: alphanumerics, dots, hyphens, and a
// final 2+ letter TLD.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$`)

// SanitizeDomain validates a domain name. Returns input on match, "" otherwise.
func SanitizeDomain(input string) string {
	if domainRe.MatchString(input) {
		return input
	}
	return ""
}

// dateTimeRe matches "YYYY-MM-DD" or "YYYY-MM-DD HH:MM" (the formats VanGuard
// use cases declare for datetime parameters).
var dateTimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$`)

// SanitizeDateTime validates a YYYY-MM-DD or YYYY-MM-DD HH:MM string.
// Returns input on match, "" otherwise.
func SanitizeDateTime(input string) string {
	if dateTimeRe.MatchString(input) {
		return input
	}
	return ""
}

// SanitizeIOC dispatches to the right validator based on a coarse IOC type
// label ("filehash" / "filename" / "ip" / "domain"). Unknown types fall back
// to SanitizeShellArg so we never let an unsanitised value through.
func SanitizeIOC(iocType, value string) string {
	switch iocType {
	case "filehash":
		return SanitizeHash(value)
	case "ip":
		return SanitizeIPAddress(value)
	case "domain":
		return SanitizeDomain(value)
	case "filename":
		// Filenames may contain wildcards (* ?) or path-like fragments.
		// SanitizeFilePath keeps the safe set; reject the value if anything
		// dangerous slips through.
		return SanitizeFilePath(value)
	}
	return SanitizeShellArg(value)
}
