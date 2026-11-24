package wrapper

import (
	"fmt"
	"strings"
)

// Mode represents how nay should handle the parsed CLI invocation.
type Mode int

const (
	ModePassthrough Mode = iota
	ModeInstall
	ModeUpgrade
	ModeAudit
	ModeConfigInit
	ModeDoctor
	ModeVersion
	ModeHelp
)

func (m Mode) String() string {
	switch m {
	case ModePassthrough:
		return "passthrough"
	case ModeInstall:
		return "install"
	case ModeUpgrade:
		return "upgrade"
	case ModeAudit:
		return "audit"
	case ModeConfigInit:
		return "config-init"
	case ModeDoctor:
		return "doctor"
	case ModeVersion:
		return "version"
	case ModeHelp:
		return "help"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// Command holds the parsed CLI arguments and nay-specific overrides.
type Command struct {
	Mode        Mode
	Targets     []string // Extracted target package names
	BackendArgs []string // Arguments with nay-specific flags stripped, ready for yay/paru

	// nay override flags
	ForceAudit bool
	NoAudit    bool
	Model      string
	Backend    string

	// config init flags
	ConfigForce bool
}

// longFlagsWithValue lists pacman, yay, and paru long flags that consume the
// next argument when not written in --flag=value form.
var longFlagsWithValue = map[string]bool{
	"--dbpath":                true,
	"--root":                  true,
	"--cachedir":              true,
	"--config":                true,
	"--gpgdir":                true,
	"--hookdir":               true,
	"--logfile":               true,
	"--arch":                  true,
	"--color":                 true,
	"--ignore":                true,
	"--ignoregroup":           true,
	"--assume-installed":      true,
	"--overwrite":             true,
	"--print-format":          true,
	"--aururl":                true,
	"--aurrpcurl":             true,
	"--builddir":              true,
	"--absdir":                true,
	"--editor":                true,
	"--editorflags":           true,
	"--makepkg":               true,
	"--makepkgconf":           true,
	"--pacman":                true,
	"--git":                   true,
	"--gitflags":              true,
	"--gpg":                   true,
	"--gpgflags":              true,
	"--mflags":                true,
	"--sudo":                  true,
	"--sudoflags":             true,
	"--sortby":                true,
	"--searchby":              true,
	"--answerclean":           true,
	"--answerdiff":            true,
	"--answeredit":            true,
	"--answerupgrade":         true,
	"--requestsplitn":         true,
	"--completioninterval":    true,
	"--maxconcurrentdownloads": true,
	"--bat":                   true,
	"--batflags":              true,
	"--fm":                    true,
	"--fmflags":               true,
	"--signkey":               true,
}

// shortFlagsWithValue lists pacman short flags that consume the next argument
// when appearing at the end of a short flag cluster.
var shortFlagsWithValue = map[byte]bool{
	'b': true, // --dbpath
	'r': true, // --root
}

// ParseArgs parses command-line arguments (excluding argv[0]) into a Command.
func ParseArgs(args []string) (*Command, error) {
	cmd := &Command{}

	// First pass: extract nay-specific override flags while preserving all
	// other arguments (including "--" and everything after it).
	var remaining []string
	afterDoubleDash := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if afterDoubleDash {
			remaining = append(remaining, arg)
			continue
		}
		if arg == "--" {
			afterDoubleDash = true
			remaining = append(remaining, arg)
			continue
		}

		switch {
		case arg == "--force-audit":
			cmd.ForceAudit = true
		case arg == "--no-audit":
			cmd.NoAudit = true
		case arg == "--model":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--model requires a value")
			}
			i++
			cmd.Model = args[i]
		case strings.HasPrefix(arg, "--model="):
			val := strings.TrimPrefix(arg, "--model=")
			if val == "" {
				return nil, fmt.Errorf("--model requires a non-empty value")
			}
			cmd.Model = val
		case arg == "--backend":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--backend requires a value (yay or paru)")
			}
			i++
			if err := validateBackend(args[i]); err != nil {
				return nil, err
			}
			cmd.Backend = args[i]
		case strings.HasPrefix(arg, "--backend="):
			val := strings.TrimPrefix(arg, "--backend=")
			if err := validateBackend(val); err != nil {
				return nil, err
			}
			cmd.Backend = val
		default:
			remaining = append(remaining, arg)
		}
	}

	cmd.BackendArgs = remaining

	// Bare `nay` -> upgrade mode (unless --no-audit is set).
	if len(remaining) == 0 {
		if cmd.NoAudit {
			cmd.Mode = ModePassthrough
		} else {
			cmd.Mode = ModeUpgrade
		}
		return cmd, nil
	}

	// Check nay-specific subcommands.
	switch remaining[0] {
	case "audit":
		cmd.Mode = ModeAudit
		for _, a := range remaining[1:] {
			if a == "--" {
				continue
			}
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown flag for audit: %s", a)
			}
			cmd.Targets = append(cmd.Targets, a)
		}
		if len(cmd.Targets) == 0 {
			return nil, fmt.Errorf("audit requires at least one package name")
		}
		return cmd, nil

	case "config":
		if len(remaining) < 2 || remaining[1] != "init" {
			return nil, fmt.Errorf("unknown config subcommand; usage: nay config init [--force]")
		}
		cmd.Mode = ModeConfigInit
		for _, a := range remaining[2:] {
			switch a {
			case "--force", "-f":
				cmd.ConfigForce = true
			default:
				return nil, fmt.Errorf("unknown flag for config init: %s", a)
			}
		}
		return cmd, nil

	case "doctor":
		cmd.Mode = ModeDoctor
		return cmd, nil

	case "version", "--version":
		cmd.Mode = ModeVersion
		return cmd, nil

	case "help", "-h", "--help":
		cmd.Mode = ModeHelp
		return cmd, nil
	}

	// If --no-audit is set, always pass straight through to yay/paru.
	if cmd.NoAudit {
		cmd.Mode = ModePassthrough
		return cmd, nil
	}

	// Classify yay/paru/pacman flags and extract target package names.
	var (
		isSync       bool
		isSysUpgrade bool
		isNonInstall bool
		targets      []string
	)

	afterDoubleDash = false
	for i := 0; i < len(remaining); i++ {
		arg := remaining[i]
		if afterDoubleDash {
			targets = append(targets, arg)
			continue
		}
		if arg == "--" {
			afterDoubleDash = true
			continue
		}

		// Long flags
		if strings.HasPrefix(arg, "--") {
			flagName := arg
			hasEq := false
			if idx := strings.IndexByte(arg, '='); idx != -1 {
				flagName = arg[:idx]
				hasEq = true
			}

			switch flagName {
			case "--sync":
				isSync = true
			case "--sysupgrade":
				isSysUpgrade = true
			case "--search", "--info", "--list", "--groups", "--clean", "--print", "--help", "--repo":
				isNonInstall = true
			}

			if !hasEq && longFlagsWithValue[flagName] {
				i++ // skip flag value
			}
			continue
		}

		// Short flag cluster (e.g., -Syu, -Ss, -Qi, -Rns)
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			flags := arg[1:]
			for j := 0; j < len(flags); j++ {
				ch := flags[j]
				switch ch {
				case 'S':
					isSync = true
				case 'u':
					isSysUpgrade = true
				case 's', 'i', 'l', 'g', 'c', 'p', 'h':
					isNonInstall = true
				}
			}
			// If the last character in the short cluster takes a value, skip the next arg.
			last := flags[len(flags)-1]
			if shortFlagsWithValue[last] {
				i++
			}
			continue
		}

		// Positional argument -> target package name.
		targets = append(targets, arg)
	}

	cmd.Targets = targets

	if !isSync || isNonInstall {
		cmd.Mode = ModePassthrough
		return cmd, nil
	}

	if isSysUpgrade {
		cmd.Mode = ModeUpgrade
		return cmd, nil
	}

	if len(targets) > 0 {
		cmd.Mode = ModeInstall
		return cmd, nil
	}

	// e.g. `nay -Sy` (refresh DB only, no targets, no upgrade)
	cmd.Mode = ModePassthrough
	return cmd, nil
}

func validateBackend(val string) error {
	if val != "yay" && val != "paru" {
		return fmt.Errorf("invalid backend %q: must be \"yay\" or \"paru\"", val)
	}
	return nil
}
