package wrapper

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeCall struct {
	interactive bool
	name        string
	args        []string
}

type fakeRunner struct {
	calls           []fakeCall
	interactiveExit int
	interactiveErr  error
	captureFunc     func(name string, args []string) ([]byte, int, error)
}

func (f *fakeRunner) RunInteractive(_ context.Context, name string, args []string) (int, error) {
	f.calls = append(f.calls, fakeCall{interactive: true, name: name, args: append([]string(nil), args...)})
	return f.interactiveExit, f.interactiveErr
}

func (f *fakeRunner) RunCapture(_ context.Context, name string, args []string) ([]byte, int, error) {
	f.calls = append(f.calls, fakeCall{interactive: false, name: name, args: append([]string(nil), args...)})
	if f.captureFunc != nil {
		return f.captureFunc(name, args)
	}
	return nil, 0, nil
}

func TestBackend_Passthrough(t *testing.T) {
	runner := &fakeRunner{interactiveExit: 42}
	b := NewBackend("paru", runner)

	code, err := b.Passthrough(context.Background(), []string{"-Qi", "bash"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 42 {
		t.Errorf("exitCode = %d, want 42", code)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(runner.calls))
	}
	c := runner.calls[0]
	if !c.interactive || c.name != "paru" || !reflect.DeepEqual(c.args, []string{"-Qi", "bash"}) {
		t.Errorf("unexpected call: %+v", c)
	}
}

func TestBackend_PendingAURUpgrades(t *testing.T) {
	t.Run("parses multiple upgrades", func(t *testing.T) {
		runner := &fakeRunner{
			captureFunc: func(name string, args []string) ([]byte, int, error) {
				if name != "yay" || !reflect.DeepEqual(args, []string{"-Qua"}) {
					t.Errorf("unexpected command: %s %v", name, args)
				}
				return []byte("ripgrep-git 14.1.0-1 -> 14.1.1-1\nvisual-studio-bin 1.95.0-1 -> 1.96.0-1\n"), 0, nil
			},
		}
		b := NewBackend("yay", runner)
		pkgs, err := b.PendingAURUpgrades(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"ripgrep-git", "visual-studio-bin"}
		if !reflect.DeepEqual(pkgs, want) {
			t.Errorf("pkgs = %v, want %v", pkgs, want)
		}
	})

	t.Run("exit 1 with empty stdout means no upgrades", func(t *testing.T) {
		runner := &fakeRunner{
			captureFunc: func(name string, args []string) ([]byte, int, error) {
				return []byte(""), 1, errors.New("exit status 1")
			},
		}
		b := NewBackend("yay", runner)
		pkgs, err := b.PendingAURUpgrades(context.Background())
		if err != nil {
			t.Fatalf("expected nil error for empty exit 1, got: %v", err)
		}
		if len(pkgs) != 0 {
			t.Errorf("expected empty slice, got %v", pkgs)
		}
	})

	t.Run("other errors propagate", func(t *testing.T) {
		runner := &fakeRunner{
			captureFunc: func(name string, args []string) ([]byte, int, error) {
				return nil, 127, errors.New("not found")
			},
		}
		b := NewBackend("yay", runner)
		if _, err := b.PendingAURUpgrades(context.Background()); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestBackend_IsRepoPackage(t *testing.T) {
	siCalls := 0
	slqCalls := 0
	runner := &fakeRunner{
		captureFunc: func(name string, args []string) ([]byte, int, error) {
			if name != "pacman" {
				t.Errorf("expected pacman, got %s", name)
			}
			if len(args) == 1 && args[0] == "-Slq" {
				slqCalls++
				return nil, 1, errors.New("slq failed")
			}
			siCalls++
			if len(args) == 3 && args[0] == "-Si" && args[1] == "--" && args[2] == "ripgrep" {
				return []byte("Name : ripgrep\n"), 0, nil
			}
			return nil, 1, errors.New("exit status 1")
		},
	}
	b := NewBackend("yay", runner)
	ctx := context.Background()

	if !b.IsRepoPackage(ctx, "ripgrep") {
		t.Error("expected ripgrep to be a repo package")
	}
	// Second call should hit cache.
	if !b.IsRepoPackage(ctx, "ripgrep") {
		t.Error("expected cached ripgrep to be a repo package")
	}
	if b.IsRepoPackage(ctx, "spotify") {
		t.Error("expected spotify not to be a repo package")
	}
	if slqCalls != 1 {
		t.Errorf("expected 1 pacman -Slq attempt, got %d", slqCalls)
	}
	if siCalls != 2 {
		t.Errorf("expected 2 pacman -Si invocations (cached repeat), got %d", siCalls)
	}
}

func TestBackend_IsRepoPackage_PreloadSlq(t *testing.T) {
	slqCalls := 0
	var siPkgs []string
	runner := &fakeRunner{
		captureFunc: func(name string, args []string) ([]byte, int, error) {
			if name != "pacman" {
				t.Errorf("expected pacman, got %s", name)
			}
			if len(args) == 1 && args[0] == "-Slq" {
				slqCalls++
				return []byte("bash\nripgrep\nglibc\n"), 0, nil
			}
			if len(args) == 3 && args[0] == "-Si" && args[1] == "--" {
				siPkgs = append(siPkgs, args[2])
				if args[2] == "sh" { // virtual provide
					return []byte("Name : bash\nProvides : sh\n"), 0, nil
				}
				return nil, 1, errors.New("not found")
			}
			return nil, 1, errors.New("unexpected args")
		},
	}
	b := NewBackend("yay", runner)
	ctx := context.Background()

	// Repo packages in -Slq should return true with zero -Si calls.
	if !b.IsRepoPackage(ctx, "bash") || !b.IsRepoPackage(ctx, "ripgrep") || !b.IsRepoPackage(ctx, "glibc") {
		t.Fatal("expected preloaded repo packages to return true")
	}
	if len(siPkgs) != 0 {
		t.Errorf("expected 0 pacman -Si calls for preloaded repo pkgs, got %v", siPkgs)
	}

	// Virtual provide falls back to -Si and caches result.
	if !b.IsRepoPackage(ctx, "sh") {
		t.Error("expected virtual provide 'sh' to resolve via pacman -Si fallback")
	}
	if !b.IsRepoPackage(ctx, "sh") {
		t.Error("expected cached virtual provide 'sh' to return true")
	}

	// Non-repo AUR package falls back to -Si, returns false, and caches result.
	if b.IsRepoPackage(ctx, "spotify") {
		t.Error("expected spotify not to be a repo package")
	}
	if b.IsRepoPackage(ctx, "spotify") {
		t.Error("expected cached spotify to remain false")
	}

	if slqCalls != 1 {
		t.Errorf("expected 1 pacman -Slq call, got %d", slqCalls)
	}
	if !reflect.DeepEqual(siPkgs, []string{"sh", "spotify"}) {
		t.Errorf("pacman -Si fallback calls = %v, want [sh spotify]", siPkgs)
	}
}

func TestBackend_InstallApproved(t *testing.T) {
	tests := []struct {
		name         string
		originalArgs []string
		skipped      []string
		wantArgs     []string
	}{
		{
			name:         "bare nay upgrade without skips",
			originalArgs: nil,
			skipped:      nil,
			wantArgs:     []string{"-Syu", "--answerdiff", "None"},
		},
		{
			name:         "upgrade with skipped packages",
			originalArgs: []string{"-Syu"},
			skipped:      []string{"evil-bin", "bad-pkg"},
			wantArgs:     []string{"-Syu", "--answerdiff", "None", "--ignore", "evil-bin,bad-pkg"},
		},
		{
			name:         "preserves existing --answerdiff",
			originalArgs: []string{"-S", "--answerdiff=All", "spotify"},
			skipped:      nil,
			wantArgs:     []string{"-S", "--answerdiff=All", "spotify"},
		},
		{
			name:         "inserts extra flags before double dash and removes skipped target",
			originalArgs: []string{"-S", "--", "pkg-a", "pkg-b"},
			skipped:      []string{"pkg-b"},
			wantArgs:     []string{"-S", "--answerdiff", "None", "--ignore", "pkg-b", "--", "pkg-a"},
		},
		{
			name:         "removes skipped explicit positional targets including aur/ prefix",
			originalArgs: []string{"-S", "--needed", "pkg-a", "aur/evil-pkg", "pkg-c"},
			skipped:      []string{"evil-pkg"},
			wantArgs:     []string{"-S", "--needed", "pkg-a", "pkg-c", "--answerdiff", "None", "--ignore", "evil-pkg"},
		},
		{
			name:         "does not strip flag values matching skipped package name",
			originalArgs: []string{"-S", "--root", "evil-pkg", "pkg-a", "evil-pkg"},
			skipped:      []string{"evil-pkg"},
			wantArgs:     []string{"-S", "--root", "evil-pkg", "pkg-a", "--answerdiff", "None", "--ignore", "evil-pkg"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{interactiveExit: 0}
			b := NewBackend("yay", runner)

			code, err := b.InstallApproved(context.Background(), tc.originalArgs, tc.skipped)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("calls = %d, want 1", len(runner.calls))
			}
			if !reflect.DeepEqual(runner.calls[0].args, tc.wantArgs) {
				t.Errorf("args = %v, want %v", runner.calls[0].args, tc.wantArgs)
			}
		})
	}
}
