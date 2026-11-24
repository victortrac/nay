package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Verdict represents the security classification of an audited package.
type Verdict string

const (
	VerdictSafe      Verdict = "SAFE"
	VerdictWarn      Verdict = "WARN"
	VerdictDangerous Verdict = "DANGEROUS"
)

// StaticFinding represents a deterministic static scanner finding for display.
type StaticFinding struct {
	Severity string // "HIGH", "WARN", "INFO"
	Code     string
	File     string
	Line     int
	Message  string
}

// RepoFile represents a file from the AUR repository for inspection.
type RepoFile struct {
	Path      string
	Content   string
	Truncated bool
}

// AuditItem holds all information rendered for one audited AUR package.
type AuditItem struct {
	PackageName string
	PackageBase string
	Version     string
	CommitSHA   string
	Verdict     Verdict
	Cached      bool
	Summary     string
	Findings    []string
	Reasoning   string
	StaticFlags []StaticFinding
	Diff        string
	Files       []RepoFile
	Error       string
}

// Decision captures the user's choice from the interactive approval prompt.
type Decision struct {
	Proceed  bool
	Approved []string
	Skipped  []string
}

// UI renders audit results and handles interactive user prompts.
type UI struct {
	In      io.Reader
	Out     io.Writer
	NoColor bool
}

// New creates a UI reading from in and writing to out, respecting NO_COLOR.
func New(in io.Reader, out io.Writer) *UI {
	_, noColor := os.LookupEnv("NO_COLOR")
	return &UI{
		In:      in,
		Out:     out,
		NoColor: noColor,
	}
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func (u *UI) color(code, text string) string {
	if u.NoColor {
		return text
	}
	return code + text + ansiReset
}

func (u *UI) formatVerdict(v Verdict, cached bool, skipped bool) string {
	label := string(v)
	if cached {
		label += " (cached)"
	}
	if skipped {
		label += " [SKIP]"
	}
	switch v {
	case VerdictSafe:
		return u.color(ansiGreen+ansiBold, label)
	case VerdictWarn:
		return u.color(ansiYellow+ansiBold, label)
	case VerdictDangerous:
		return u.color(ansiRed+ansiBold, label)
	default:
		return label
	}
}

// RenderTable prints the summary table of all audited packages.
func (u *UI) RenderTable(items []AuditItem, skipped map[string]bool) {
	if len(items) == 0 {
		return
	}

	pkgW := len("PACKAGE")
	verW := len("VERSION")
	comW := len("COMMIT")
	flgW := len("STATIC FLAGS")

	type row struct {
		pkg     string
		ver     string
		commit  string
		flags   string
		verdict string
	}

	rows := make([]row, 0, len(items))
	for _, it := range items {
		shortSHA := it.CommitSHA
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		if shortSHA == "" {
			shortSHA = "-"
		}

		ver := it.Version
		if ver == "" {
			ver = "-"
		}

		flags := formatFlagSummary(it.StaticFlags)
		if len(flags) > 28 {
			flags = flags[:25] + "..."
		}

		isSkipped := skipped != nil && skipped[it.PackageName]
		r := row{
			pkg:     it.PackageName,
			ver:     ver,
			commit:  shortSHA,
			flags:   flags,
			verdict: u.formatVerdict(it.Verdict, it.Cached, isSkipped),
		}
		if len(r.pkg) > pkgW {
			pkgW = len(r.pkg)
		}
		if len(r.ver) > verW {
			verW = len(r.ver)
		}
		if len(r.commit) > comW {
			comW = len(r.commit)
		}
		if len(r.flags) > flgW {
			flgW = len(r.flags)
		}
		rows = append(rows, r)
	}

	fmt.Fprintln(u.Out)
	header := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %s",
		pkgW, "PACKAGE", verW, "VERSION", comW, "COMMIT", flgW, "STATIC FLAGS", "VERDICT")
	fmt.Fprintln(u.Out, u.color(ansiBold, header))
	ruleLen := pkgW + verW + comW + flgW + 20
	fmt.Fprintf(u.Out, "  %s\n", strings.Repeat("─", ruleLen))

	for _, r := range rows {
		fmt.Fprintf(u.Out, "  %-*s  %-*s  %-*s  %-*s  %s\n",
			pkgW, r.pkg, verW, r.ver, comW, r.commit, flgW, r.flags, r.verdict)
	}
	fmt.Fprintln(u.Out)
}

// RenderFindings prints static and LLM analysis summaries for all audited packages.
func (u *UI) RenderFindings(items []AuditItem) {
	for _, it := range items {
		prefix := "[ok]"
		colorCode := ansiGreen + ansiBold
		if it.Verdict == VerdictDangerous || it.Error != "" {
			prefix = "[!]"
			colorCode = ansiRed + ansiBold
		} else if it.Verdict == VerdictWarn {
			prefix = "[?]"
			colorCode = ansiYellow + ansiBold
		}

		heading := fmt.Sprintf("%s %s (%s):", prefix, it.PackageName, it.Verdict)
		fmt.Fprintf(u.Out, "  %s\n", u.color(colorCode, heading))

		if it.Error != "" {
			fmt.Fprintf(u.Out, "      - Error: %s\n", it.Error)
		}
		if len(it.StaticFlags) > 0 {
			msgs := make([]string, 0, len(it.StaticFlags))
			for _, sf := range it.StaticFlags {
				loc := sf.File
				if sf.Line > 0 {
					loc = fmt.Sprintf("%s:%d", sf.File, sf.Line)
				}
				if loc != "" {
					msgs = append(msgs, fmt.Sprintf("[%s] %s (%s)", sf.Severity, sf.Message, loc))
				} else {
					msgs = append(msgs, fmt.Sprintf("[%s] %s", sf.Severity, sf.Message))
				}
			}
			fmt.Fprintf(u.Out, "      - Static: %s\n", strings.Join(msgs, "; "))
		}
		if it.Summary != "" {
			fmt.Fprintf(u.Out, "      - LLM: %s\n", it.Summary)
		}
		for _, f := range it.Findings {
			fmt.Fprintf(u.Out, "        * %s\n", f)
		}
		fmt.Fprintln(u.Out)
	}
}

// RenderInspect prints the full inspection report for a single package.
func (u *UI) RenderInspect(it AuditItem) {
	sep := strings.Repeat("═", 72)
	fmt.Fprintf(u.Out, "\n%s\n", u.color(ansiCyan+ansiBold, sep))
	fmt.Fprintf(u.Out, "%s %s (%s)  commit=%s  verdict=%s\n",
		u.color(ansiBold, "PACKAGE:"), it.PackageName, it.Version, it.CommitSHA,
		u.formatVerdict(it.Verdict, it.Cached, false))
	fmt.Fprintf(u.Out, "%s\n", u.color(ansiCyan+ansiBold, sep))

	if it.Error != "" {
		fmt.Fprintf(u.Out, "\n%s %s\n", u.color(ansiRed+ansiBold, "ERROR:"), it.Error)
	}

	fmt.Fprintf(u.Out, "\n%s\n", u.color(ansiBold, "STATIC FLAGS:"))
	if len(it.StaticFlags) == 0 {
		fmt.Fprintln(u.Out, "  none")
	} else {
		for _, sf := range it.StaticFlags {
			loc := sf.File
			if sf.Line > 0 {
				loc = fmt.Sprintf("%s:%d", sf.File, sf.Line)
			}
			if loc != "" {
				fmt.Fprintf(u.Out, "  - [%s] %s (%s): %s\n", sf.Severity, sf.Code, loc, sf.Message)
			} else {
				fmt.Fprintf(u.Out, "  - [%s] %s: %s\n", sf.Severity, sf.Code, sf.Message)
			}
		}
	}

	fmt.Fprintf(u.Out, "\n%s\n", u.color(ansiBold, "LLM SUMMARY:"))
	if it.Summary != "" {
		fmt.Fprintf(u.Out, "  %s\n", it.Summary)
	} else {
		fmt.Fprintln(u.Out, "  (none)")
	}

	if len(it.Findings) > 0 {
		fmt.Fprintf(u.Out, "\n%s\n", u.color(ansiBold, "LLM FINDINGS:"))
		for _, f := range it.Findings {
			fmt.Fprintf(u.Out, "  - %s\n", f)
		}
	}

	if it.Reasoning != "" {
		fmt.Fprintf(u.Out, "\n%s\n%s\n", u.color(ansiBold, "LLM REASONING:"), it.Reasoning)
	}

	if strings.TrimSpace(it.Diff) != "" {
		fmt.Fprintf(u.Out, "\n%s\n%s\n", u.color(ansiBold, "GIT DIFF:"), it.Diff)
	}

	if len(it.Files) > 0 {
		fmt.Fprintf(u.Out, "\n%s\n", u.color(ansiBold, "REPOSITORY FILES:"))
		for _, f := range it.Files {
			note := ""
			if f.Truncated {
				note = " (truncated)"
			}
			fmt.Fprintf(u.Out, "--- %s%s ---\n%s\n", f.Path, note, f.Content)
		}
	}
	fmt.Fprintln(u.Out)
}

// Prompt displays the verdict table and findings, then runs an interactive
// approval loop until the user proceeds or quits.
func (u *UI) Prompt(items []AuditItem) (Decision, error) {
	byName := make(map[string]AuditItem, len(items))
	skipped := make(map[string]bool)
	for _, it := range items {
		byName[it.PackageName] = it
		if it.Verdict == VerdictDangerous {
			skipped[it.PackageName] = true
		}
	}

	u.RenderTable(items, skipped)
	u.RenderFindings(items)

	scanner := bufio.NewScanner(u.In)
	for {
		u.printPromptLine(items, skipped)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return Decision{Proceed: false}, err
			}
			fmt.Fprintln(u.Out)
			return Decision{Proceed: false}, nil
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		verb := strings.ToLower(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch verb {
		case "p", "proceed":
			approved, sk := partitionPackages(items, skipped)
			if len(approved) == 0 {
				fmt.Fprintln(u.Out, u.color(ansiYellow, "All packages are currently skipped. Use [s]kip <pkg> to unskip, [a]ll to approve all, or [q]uit."))
				continue
			}
			return Decision{Proceed: true, Approved: approved, Skipped: sk}, nil

		case "q", "quit", "n", "no":
			return Decision{Proceed: false}, nil

		case "i", "inspect":
			if arg == "" {
				if len(items) == 1 {
					arg = items[0].PackageName
				} else {
					fmt.Fprintln(u.Out, "Usage: i <package>")
					continue
				}
			}
			it, ok := byName[arg]
			if !ok {
				fmt.Fprintf(u.Out, "Unknown package %q.\n", arg)
				continue
			}
			u.RenderInspect(it)

		case "s", "skip":
			if arg == "" {
				if len(items) == 1 {
					arg = items[0].PackageName
				} else {
					fmt.Fprintln(u.Out, "Usage: s <package>")
					continue
				}
			}
			if _, ok := byName[arg]; !ok {
				fmt.Fprintf(u.Out, "Unknown package %q.\n", arg)
				continue
			}
			if skipped[arg] {
				delete(skipped, arg)
				fmt.Fprintf(u.Out, "Marked %s to INSTALL.\n", arg)
			} else {
				skipped[arg] = true
				fmt.Fprintf(u.Out, "Marked %s as SKIPPED.\n", arg)
			}
			u.RenderTable(items, skipped)

		case "a", "all":
			var dangerous []string
			for _, it := range items {
				if it.Verdict == VerdictDangerous {
					dangerous = append(dangerous, it.PackageName)
				}
			}
			if len(dangerous) > 0 {
				fmt.Fprintf(u.Out, "%s Including DANGEROUS package(s): %s. Type \"yes\" to confirm: ",
					u.color(ansiRed+ansiBold, "WARNING:"), strings.Join(dangerous, ", "))
				if !scanner.Scan() {
					if err := scanner.Err(); err != nil {
						return Decision{Proceed: false}, err
					}
					return Decision{Proceed: false}, nil
				}
				if strings.ToLower(strings.TrimSpace(scanner.Text())) != "yes" {
					fmt.Fprintln(u.Out, "Confirmation declined; returning to menu.")
					continue
				}
			}
			allApproved := make([]string, 0, len(items))
			for _, it := range items {
				allApproved = append(allApproved, it.PackageName)
			}
			return Decision{Proceed: true, Approved: allApproved, Skipped: nil}, nil

		case "t", "table", "l", "list":
			u.RenderTable(items, skipped)

		default:
			fmt.Fprintf(u.Out, "Unknown action %q. Valid actions: [p]roceed, [i]nspect <pkg>, [s]kip <pkg>, [a]ll, [q]uit.\n", verb)
		}
	}
}

func (u *UI) printPromptLine(items []AuditItem, skipped map[string]bool) {
	skipCount := len(skipped)
	proceedLabel := "[p]roceed"
	if skipCount > 0 {
		proceedLabel = fmt.Sprintf("[p]roceed (skip %d)", skipCount)
	}
	fmt.Fprintf(u.Out, "%s %s, [i]nspect <pkg>, [s]kip <pkg>, [a]ll, [q]uit > ",
		u.color(ansiBold, "Action:"), proceedLabel)
}

func partitionPackages(items []AuditItem, skipped map[string]bool) (approved, sk []string) {
	for _, it := range items {
		if skipped[it.PackageName] {
			sk = append(sk, it.PackageName)
		} else {
			approved = append(approved, it.PackageName)
		}
	}
	return approved, sk
}

func formatFlagSummary(flags []StaticFinding) string {
	if len(flags) == 0 {
		return "none"
	}
	seen := make(map[string]bool, len(flags))
	codes := make([]string, 0, len(flags))
	for _, f := range flags {
		label := f.Code
		if label == "" {
			label = f.Message
		}
		if !seen[label] {
			seen[label] = true
			codes = append(codes, label)
		}
	}
	return strings.Join(codes, ", ")
}
