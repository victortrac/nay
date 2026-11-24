package wrapper

import (
	"reflect"
	"testing"
)

func TestParseArgs_Subcommands(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantMode    Mode
		wantTargets []string
		wantForce   bool
		wantModel   string
		wantBackend string
		wantCfgFrc  bool
		wantErr     bool
	}{
		{
			name:        "audit single package",
			args:        []string{"audit", "spotify"},
			wantMode:    ModeAudit,
			wantTargets: []string{"spotify"},
		},
		{
			name:        "audit multiple packages with override flags",
			args:        []string{"--force-audit", "--model", "gemini-2.5-pro", "audit", "pkg-a", "pkg-b"},
			wantMode:    ModeAudit,
			wantTargets: []string{"pkg-a", "pkg-b"},
			wantForce:   true,
			wantModel:   "gemini-2.5-pro",
		},
		{
			name:        "audit with flags after subcommand",
			args:        []string{"audit", "pkg-a", "--force-audit", "--backend=paru"},
			wantMode:    ModeAudit,
			wantTargets: []string{"pkg-a"},
			wantForce:   true,
			wantBackend: "paru",
		},
		{
			name:    "audit without packages errors",
			args:    []string{"audit"},
			wantErr: true,
		},
		{
			name:     "config init",
			args:     []string{"config", "init"},
			wantMode: ModeConfigInit,
		},
		{
			name:       "config init force",
			args:       []string{"config", "init", "--force"},
			wantMode:   ModeConfigInit,
			wantCfgFrc: true,
		},
		{
			name:    "config invalid subcommand",
			args:    []string{"config", "edit"},
			wantErr: true,
		},
		{
			name:     "doctor",
			args:     []string{"doctor"},
			wantMode: ModeDoctor,
		},
		{
			name:     "version",
			args:     []string{"version"},
			wantMode: ModeVersion,
		},
		{
			name:     "help flag",
			args:     []string{"--help"},
			wantMode: ModeHelp,
		},
		{
			name:     "help subcommand",
			args:     []string{"help"},
			wantMode: ModeHelp,
		},
		{
			name:    "invalid backend",
			args:    []string{"--backend", "pacman", "-Syu"},
			wantErr: true,
		},
		{
			name:    "missing model value",
			args:    []string{"--model"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := ParseArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (cmd=%+v)", cmd)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd.Mode != tc.wantMode {
				t.Errorf("Mode = %v, want %v", cmd.Mode, tc.wantMode)
			}
			if !reflect.DeepEqual(cmd.Targets, tc.wantTargets) {
				t.Errorf("Targets = %v, want %v", cmd.Targets, tc.wantTargets)
			}
			if cmd.ForceAudit != tc.wantForce {
				t.Errorf("ForceAudit = %v, want %v", cmd.ForceAudit, tc.wantForce)
			}
			if cmd.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", cmd.Model, tc.wantModel)
			}
			if cmd.Backend != tc.wantBackend {
				t.Errorf("Backend = %q, want %q", cmd.Backend, tc.wantBackend)
			}
			if cmd.ConfigForce != tc.wantCfgFrc {
				t.Errorf("ConfigForce = %v, want %v", cmd.ConfigForce, tc.wantCfgFrc)
			}
		})
	}
}

func TestParseArgs_WrapperModes(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantMode        Mode
		wantTargets     []string
		wantBackendArgs []string
		wantForce       bool
		wantNoAudit     bool
		wantModel       string
		wantBackend     string
	}{
		{
			name:            "bare nay is upgrade",
			args:            nil,
			wantMode:        ModeUpgrade,
			wantBackendArgs: nil,
		},
		{
			name:            "bare nay with --no-audit is passthrough",
			args:            []string{"--no-audit"},
			wantMode:        ModePassthrough,
			wantNoAudit:     true,
			wantBackendArgs: nil,
		},
		{
			name:            "-Syu is upgrade",
			args:            []string{"-Syu"},
			wantMode:        ModeUpgrade,
			wantBackendArgs: []string{"-Syu"},
		},
		{
			name:            "-Sua is upgrade",
			args:            []string{"-Sua"},
			wantMode:        ModeUpgrade,
			wantBackendArgs: []string{"-Sua"},
		},
		{
			name:            "-Su with extra target is upgrade with target",
			args:            []string{"-Su", "spotify"},
			wantMode:        ModeUpgrade,
			wantTargets:     []string{"spotify"},
			wantBackendArgs: []string{"-Su", "spotify"},
		},
		{
			name:            "long --sync --sysupgrade",
			args:            []string{"--sync", "--sysupgrade"},
			wantMode:        ModeUpgrade,
			wantBackendArgs: []string{"--sync", "--sysupgrade"},
		},
		{
			name:            "-S single target is install",
			args:            []string{"-S", "spotify"},
			wantMode:        ModeInstall,
			wantTargets:     []string{"spotify"},
			wantBackendArgs: []string{"-S", "spotify"},
		},
		{
			name:            "-S with flags taking values ignores flag values",
			args:            []string{"-S", "--needed", "--ignore", "foo,bar", "--color=always", "-r", "/mnt", "pkg1", "pkg2"},
			wantMode:        ModeInstall,
			wantTargets:     []string{"pkg1", "pkg2"},
			wantBackendArgs: []string{"-S", "--needed", "--ignore", "foo,bar", "--color=always", "-r", "/mnt", "pkg1", "pkg2"},
		},
		{
			name:            "-S strips nay override flags from backend args",
			args:            []string{"-S", "--force-audit", "--model=claude-sonnet-4-5", "--backend", "paru", "yay-bin"},
			wantMode:        ModeInstall,
			wantTargets:     []string{"yay-bin"},
			wantBackendArgs: []string{"-S", "yay-bin"},
			wantForce:       true,
			wantModel:       "claude-sonnet-4-5",
			wantBackend:     "paru",
		},
		{
			name:            "-S with --no-audit is passthrough",
			args:            []string{"--no-audit", "-S", "spotify"},
			wantMode:        ModePassthrough,
			wantNoAudit:     true,
			wantBackendArgs: []string{"-S", "spotify"},
		},
		{
			name:            "-Ss search is passthrough",
			args:            []string{"-Ss", "neovim"},
			wantMode:        ModePassthrough,
			wantTargets:     []string{"neovim"},
			wantBackendArgs: []string{"-Ss", "neovim"},
		},
		{
			name:            "-Si info is passthrough",
			args:            []string{"-Si", "bash"},
			wantMode:        ModePassthrough,
			wantTargets:     []string{"bash"},
			wantBackendArgs: []string{"-Si", "bash"},
		},
		{
			name:            "-Qi query info is passthrough",
			args:            []string{"-Qi", "ripgrep"},
			wantMode:        ModePassthrough,
			wantTargets:     []string{"ripgrep"},
			wantBackendArgs: []string{"-Qi", "ripgrep"},
		},
		{
			name:            "-Rns remove is passthrough",
			args:            []string{"-Rns", "unused-pkg"},
			wantMode:        ModePassthrough,
			wantTargets:     []string{"unused-pkg"},
			wantBackendArgs: []string{"-Rns", "unused-pkg"},
		},
		{
			name:            "-Sc clean is passthrough",
			args:            []string{"-Sc"},
			wantMode:        ModePassthrough,
			wantBackendArgs: []string{"-Sc"},
		},
		{
			name:            "-Sy without targets or -u is passthrough",
			args:            []string{"-Sy"},
			wantMode:        ModePassthrough,
			wantBackendArgs: []string{"-Sy"},
		},
		{
			name:            "-S --repo is passthrough",
			args:            []string{"-S", "--repo", "ripgrep"},
			wantMode:        ModePassthrough,
			wantTargets:     []string{"ripgrep"},
			wantBackendArgs: []string{"-S", "--repo", "ripgrep"},
		},
		{
			name:            "double dash stops flag parsing",
			args:            []string{"-S", "--", "--not-a-flag"},
			wantMode:        ModeInstall,
			wantTargets:     []string{"--not-a-flag"},
			wantBackendArgs: []string{"-S", "--", "--not-a-flag"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := ParseArgs(tc.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd.Mode != tc.wantMode {
				t.Errorf("Mode = %v, want %v", cmd.Mode, tc.wantMode)
			}
			if !reflect.DeepEqual(cmd.Targets, tc.wantTargets) {
				t.Errorf("Targets = %v, want %v", cmd.Targets, tc.wantTargets)
			}
			if !reflect.DeepEqual(cmd.BackendArgs, tc.wantBackendArgs) {
				t.Errorf("BackendArgs = %v, want %v", cmd.BackendArgs, tc.wantBackendArgs)
			}
			if cmd.ForceAudit != tc.wantForce {
				t.Errorf("ForceAudit = %v, want %v", cmd.ForceAudit, tc.wantForce)
			}
			if cmd.NoAudit != tc.wantNoAudit {
				t.Errorf("NoAudit = %v, want %v", cmd.NoAudit, tc.wantNoAudit)
			}
			if cmd.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", cmd.Model, tc.wantModel)
			}
			if cmd.Backend != tc.wantBackend {
				t.Errorf("Backend = %q, want %q", cmd.Backend, tc.wantBackend)
			}
		})
	}
}
