package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity represents the risk level of a static red-flag finding.
type Severity string

const (
	SeverityInfo Severity = "INFO"
	SeverityWarn Severity = "WARN"
	SeverityHigh Severity = "HIGH"
)

// Flag represents a single deterministic static analysis finding.
type Flag struct {
	Severity Severity
	Code     string
	File     string
	Message  string
}

// String formats a Flag for human-readable display or LLM context.
func (f Flag) String() string {
	if f.File != "" {
		return fmt.Sprintf("[%s] %s (%s): %s", f.Severity, f.Code, f.File, f.Message)
	}
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Code, f.Message)
}

// File represents a file inside an AUR package repository.
type File struct {
	Path    string
	Content string
}

// Input holds the AUR metadata and repository files to scan.
type Input struct {
	PackageName    string
	NumVotes       int
	Popularity     float64
	Maintainer     string
	FirstSubmitted int64
	LastModified   int64
	OutOfDate      int64
	Files          []File
	Now            time.Time // Optional; defaults to time.Now() if zero.
}

var (
	// curl/wget piped to an interpreter: curl ... | sh, wget ... | sudo bash, etc.
	rePipeToShell = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:/(?:usr/)?bin/)?(?:python3?|perl)\b`)
	// Process substitution: bash <(curl ...), sh <(wget ...)
	reProcSubShell = regexp.MustCompile(`(?i)\b(?:(?:ba|z|da|k)?sh|python3?|perl)\b[^\n]*<\(\s*(?:curl|wget)\b`)

	// base64 decoding: base64 -d, base64 --decode, base64 -D, base64 -di, base64 -id
	reBase64Decode = regexp.MustCompile(`(?i)\bbase64\b[^\n]*(?:\s--decode\b|\s-[a-zA-Z]*[dD][a-zA-Z]*\b)`)

	// shell eval invocation (avoiding words like evaluate, retval, or --eval flags)
	reShellEval = regexp.MustCompile(`(?:^|[;&|(\s])eval(?:\s|$)`)

	// Prompt injection patterns (evaluated case-insensitively across all text including comments)
	rePromptInjection = regexp.MustCompile(`(?i)(?:` + strings.Join([]string{
		`ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions`,
		`disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions`,
		`forget\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions`,
		`override\s+(?:the\s+)?(?:system|your)\s+(?:prompt|instructions)`,
		`mark\s+this\s+(?:package\s+)?(?:as\s+)?safe`,
		`verdict\s*[:=]\s*["']?safe["']?`,
		`classify\s+(?:this\s+)?(?:package\s+)?as\s+safe`,
		`report\s+(?:this\s+)?(?:package\s+)?as\s+safe`,
		`return\s+["']?safe["']?\s+(?:verdict|as\s+the\s+verdict)`,
		`do\s+not\s+(?:flag|report|warn)\s+(?:this|any)`,
		`<\|im_start\|>system`,
	}, "|") + `)`)

	// HTTP/HTTPS URLs
	reURL = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>(){}\[\]]+`)

	// Raw IPv4 host
	reIPv4 = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)

	// Array assignments in PKGBUILD: source=(...), source_x86_64=(...), sha256sums=(...), etc.
	reArrayAssign = regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9_]+)\+?=\(([^)]*)\)`)

	// PKGBUILD install= directive
	reInstallDirective = regexp.MustCompile(`(?m)^\s*install\s*=\s*['"]?([^\s'"#]+)['"]?`)
)

var suspiciousHosts = []string{
	"pastebin.com",
	"paste.rs",
	"transfer.sh",
	"tmpfiles.org",
	"0x0.st",
	"hastebin.com",
	"dpaste.org",
	"ix.io",
	"sprunge.us",
	"termbin.com",
	"file.io",
	"catbox.moe",
	"litterbox.catbox.moe",
	"ngrok.io",
	"ngrok-free.app",
}

// Scan runs deterministic security checks on the AUR metadata and repository files.
func Scan(in Input) []Flag {
	var flags []Flag

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	// 1. Metadata checks
	if in.PackageName != "" {
		if strings.TrimSpace(in.Maintainer) == "" {
			flags = append(flags, Flag{
				Severity: SeverityWarn,
				Code:     "orphaned-package",
				Message:  "package is orphaned (no maintainer)",
			})
		}
		if in.FirstSubmitted > 0 && in.NumVotes == 0 {
			submittedAt := time.Unix(in.FirstSubmitted, 0)
			age := now.Sub(submittedAt)
			if age <= 14*24*time.Hour {
				flags = append(flags, Flag{
					Severity: SeverityWarn,
					Code:     "new-zero-votes",
					Message:  fmt.Sprintf("0 votes and submitted recently (%s ago)", formatAge(age)),
				})
			}
		}
	}

	// 2. Per-file checks
	hasInstallFile := false
	for _, f := range in.Files {
		if strings.HasSuffix(strings.ToLower(f.Path), ".install") {
			hasInstallFile = true
			flags = append(flags, Flag{
				Severity: SeverityWarn,
				Code:     "install-script",
				File:     f.Path,
				Message:  "includes .install script (hooks run as root during pacman transactions)",
			})
		}

		// Hidden / bidirectional Unicode characters (scan entire content including comments)
		if codepoints := findHiddenUnicode(f.Content); len(codepoints) > 0 {
			sample := codepoints
			if len(sample) > 5 {
				sample = sample[:5]
			}
			flags = append(flags, Flag{
				Severity: SeverityHigh,
				Code:     "hidden-unicode",
				File:     f.Path,
				Message:  fmt.Sprintf("contains %d hidden or bidirectional Unicode character(s) (e.g. %s)", len(codepoints), strings.Join(sample, ", ")),
			})
		}

		// Prompt injection patterns (scan entire content including comments)
		if match := rePromptInjection.FindString(f.Content); match != "" {
			flags = append(flags, Flag{
				Severity: SeverityHigh,
				Code:     "prompt-injection",
				File:     f.Path,
				Message:  fmt.Sprintf("potential prompt-injection phrase detected: %q", match),
			})
		}

		// Shell / code checks on non-comment lines (strip comments before joining backslash continuations,
		// since bash comments end at newline and ignore trailing backslashes).
		codeText := joinContinuations(stripShellComments(f.Content))

		if rePipeToShell.MatchString(codeText) || reProcSubShell.MatchString(codeText) {
			flags = append(flags, Flag{
				Severity: SeverityHigh,
				Code:     "curl-pipe-shell",
				File:     f.Path,
				Message:  "downloads remote content and pipes/passes it directly to a shell or interpreter",
			})
		}

		if reBase64Decode.MatchString(codeText) {
			flags = append(flags, Flag{
				Severity: SeverityHigh,
				Code:     "base64-decode",
				File:     f.Path,
				Message:  "uses base64 decoding (often used to obfuscate payloads)",
			})
		}

		if reShellEval.MatchString(codeText) {
			flags = append(flags, Flag{
				Severity: SeverityHigh,
				Code:     "shell-eval",
				File:     f.Path,
				Message:  "uses shell eval (dynamic command execution)",
			})
		}

		// Suspicious download URLs (raw IPs, pastebins, ephemeral file hosts)
		if susURLs := findSuspiciousURLs(codeText); len(susURLs) > 0 {
			for _, u := range susURLs {
				flags = append(flags, Flag{
					Severity: SeverityHigh,
					Code:     "suspicious-url",
					File:     f.Path,
					Message:  fmt.Sprintf("suspicious download URL: %s", u),
				})
			}
		}

		// SKIP checksums on non-VCS sources in PKGBUILD
		if isPKGBUILD(f.Path) {
			if skipCount := countNonVCSSkipChecksums(f.Content); skipCount > 0 {
				flags = append(flags, Flag{
					Severity: SeverityWarn,
					Code:     "skip-checksum",
					File:     f.Path,
					Message:  fmt.Sprintf("uses SKIP checksum on %d non-VCS source(s)", skipCount),
				})
			}
		}
	}

	// If PKGBUILD references an install= script that wasn't already flagged via a .install file
	if !hasInstallFile {
		for _, f := range in.Files {
			if isPKGBUILD(f.Path) {
				if m := reInstallDirective.FindStringSubmatch(stripShellComments(f.Content)); len(m) > 1 {
					flags = append(flags, Flag{
						Severity: SeverityWarn,
						Code:     "install-script",
						File:     f.Path,
						Message:  fmt.Sprintf("PKGBUILD declares install=%s (hooks run as root)", m[1]),
					})
					break
				}
			}
		}
	}

	return flags
}

func isPKGBUILD(path string) bool {
	base := path
	if idx := strings.LastIndexAny(path, "/\\"); idx >= 0 {
		base = path[idx+1:]
	}
	return base == "PKGBUILD"
}

func findHiddenUnicode(s string) []string {
	var found []string
	for i, r := range s {
		if r == '\uFEFF' && i == 0 {
			// Standard UTF-8 BOM at start of file is benign.
			continue
		}
		if isHiddenOrBidi(r) {
			found = append(found, fmt.Sprintf("U+%04X", r))
		}
	}
	return found
}

func isHiddenOrBidi(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // Bidi embeddings & overrides (Trojan Source)
		return true
	case r >= 0x2066 && r <= 0x2069: // Bidi isolates (Trojan Source)
		return true
	case r == 0x200B || r == 0x200C || r == 0x200D: // Zero-width space/non-joiner/joiner
		return true
	case r == 0x200E || r == 0x200F || r == 0x061C: // LRM, RLM, ALM
		return true
	case r == 0x2060 || r == 0xFEFF || r == 0x00AD: // Word joiner, ZWNBSP, soft hyphen
		return true
	default:
		return false
	}
}

func joinContinuations(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\\\n", " ")
}

func stripShellComments(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func findSuspiciousURLs(s string) []string {
	matches := reURL.FindAllString(s, -1)
	seen := make(map[string]bool)
	var result []string
	for _, raw := range matches {
		// Trim common trailing punctuation.
		raw = strings.TrimRight(raw, ".,;:")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if isSuspiciousHost(host, u.Path) {
			if !seen[raw] {
				seen[raw] = true
				result = append(result, raw)
			}
		}
	}
	return result
}

func isSuspiciousHost(host, path string) bool {
	if reIPv4.MatchString(host) {
		return true
	}
	// IPv6 literal host (url.Hostname() strips brackets, leaving colons).
	if strings.Contains(host, ":") {
		return true
	}
	for _, bad := range suspiciousHosts {
		if host == bad || strings.HasSuffix(host, "."+bad) {
			return true
		}
	}
	if host == "cdn.discordapp.com" && strings.HasPrefix(strings.ToLower(path), "/attachments/") {
		return true
	}
	if (host == "discord.com" || host == "discordapp.com") && strings.HasPrefix(strings.ToLower(path), "/api/webhooks/") {
		return true
	}
	return false
}

func countNonVCSSkipChecksums(pkgbuild string) int {
	clean := stripShellComments(pkgbuild)
	sources := make(map[string][]string) // suffix ("" or "_x86_64") -> items
	sums := make(map[string][]string)    // suffix -> items (from first matching *sums array per suffix)

	for _, m := range reArrayAssign.FindAllStringSubmatch(clean, -1) {
		name := m[1]
		items := parseBashArrayItems(m[2])
		if name == "source" {
			sources[""] = append(sources[""], items...)
		} else if strings.HasPrefix(name, "source_") {
			suffix := strings.TrimPrefix(name, "source")
			sources[suffix] = append(sources[suffix], items...)
		} else if suffix, ok := checksumArraySuffix(name); ok {
			sums[suffix] = append(sums[suffix], items...)
		}
	}

	skipCount := 0
	for suffix, sumItems := range sums {
		srcItems := sources[suffix]
		for i, sum := range sumItems {
			if strings.EqualFold(sum, "SKIP") {
				if i < len(srcItems) {
					if !isVCSSource(srcItems[i]) {
						skipCount++
					}
				} else {
					skipCount++
				}
			}
		}
	}
	return skipCount
}

func checksumArraySuffix(name string) (string, bool) {
	prefixes := []string{"sha256sums", "sha512sums", "sha384sums", "sha224sums", "sha1sums", "md5sums", "b2sums", "cksums"}
	for _, p := range prefixes {
		if name == p {
			return "", true
		}
		if strings.HasPrefix(name, p+"_") {
			return strings.TrimPrefix(name, p), true
		}
	}
	return "", false
}

func isVCSSource(src string) bool {
	// Strip optional "localname::" prefix.
	if idx := strings.Index(src, "::"); idx >= 0 {
		src = src[idx+2:]
	}
	lower := strings.ToLower(src)
	for _, prefix := range []string{"git+", "hg+", "svn+", "bzr+"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func parseBashArrayItems(body string) []string {
	var items []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	inToken := false

	for i := 0; i < len(body); {
		r, w := utf8.DecodeRuneInString(body[i:])
		i += w

		if inSingle {
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}
			continue
		}
		if inDouble {
			if r == '"' {
				inDouble = false
			} else {
				cur.WriteRune(r)
			}
			continue
		}

		switch r {
		case '\'':
			inSingle = true
			inToken = true
		case '"':
			inDouble = true
			inToken = true
		case ' ', '\t', '\n', '\r':
			if inToken {
				items = append(items, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if inToken {
		items = append(items, cur.String())
	}
	return items
}

func formatAge(d time.Duration) string {
	if d < 0 {
		return "0h"
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours < 1 {
			return "<1h"
		}
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
