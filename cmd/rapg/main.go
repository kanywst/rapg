package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/awnumar/memguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/rapg/internal/audit"
	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/core"
	"github.com/kanywst/rapg/internal/storage"
	"github.com/kanywst/rapg/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	if err := storage.InitDB(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "rapg",
		Short: "The Developer-First Secret Manager",
		Long:  `Rapg is a secure vault for your secrets, designed to replace .env files and unsecure sharing methods.`,
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(ui.NewModel(), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error running program: %v\n", err)
				os.Exit(1)
			}
		},
	}

	genCmd := &cobra.Command{
		Use:   "gen [length]",
		Short: "Generate a random password",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			length := 24
			if len(args) > 0 {
				val, err := strconv.Atoi(args[0])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error parsing length: %v\n", err)
					return
				}
				length = val
			}
			pass, err := core.GenerateRandomPassword(length)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			fmt.Println(pass)
		},
	}

	nukeCmd := &cobra.Command{
		Use:   "nuke",
		Short: "Delete all data (Destructive)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("Are you sure? This will delete all passwords. [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading confirmation: %v\n", err)
				return
			}
			response = strings.TrimSpace(strings.ToLower(response))

			if response == "y" || response == "yes" {
				home, err := os.UserHomeDir()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
					return
				}
				configDir := filepath.Join(home, ".rapg")

				// Delete only database related files
				files, err := filepath.Glob(filepath.Join(configDir, "rapg.db*"))
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error finding database files: %v\n", err)
					return
				}
				for _, f := range files {
					if err := os.Remove(f); err != nil {
						fmt.Fprintf(os.Stderr, "Error removing file %s: %v\n", f, err)
					}
				}
				fmt.Println("Nuked.")
			} else {
				fmt.Println("Aborted.")
			}
		},
	}

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export secrets with EnvKey set to .env format",
		Run: func(cmd *cobra.Command, args []string) {
			project := loadProject()
			unlockVault()

			envVars, err := core.GetEnvVars(project)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting env vars: %v\n", err)
				os.Exit(1)
			}

			for k, v := range envVars {
				if strings.ContainsAny(v, " \n#=\"") {
					escapedV := strings.ReplaceAll(v, "\"", "\\\"")
					escapedV = strings.ReplaceAll(escapedV, "\n", "\\n")
					fmt.Printf("%s=\"%s\"\n", k, escapedV)
				} else {
					fmt.Printf("%s=%s\n", k, v)
				}
			}
		},
	}

	runCmd := &cobra.Command{
		Use:   "run -- <command>",
		Short: "Run a command with secrets injected as environment variables",
		Long: `Run a command with secrets injected as environment variables.
Note: Secrets configured in Rapg will override any existing environment variables with the same name.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			project := loadProject()
			unlockVault()

			envVars, err := core.GetEnvVars(project)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting env vars: %v\n", err)
				os.Exit(1)
			}

			command := args[0]
			cmdArgs := args[1:]

			// #nosec G204
			runCmd := exec.Command(command, cmdArgs...)
			runCmd.Stdin = os.Stdin
			runCmd.Stdout = os.Stdout
			runCmd.Stderr = os.Stderr

			// Filter existing environment variables to ensure secrets override them correctly
			runCmd.Env = make([]string, 0, len(os.Environ())+len(envVars))
			for _, e := range os.Environ() {
				key := strings.SplitN(e, "=", 2)[0]
				if _, ok := envVars[key]; !ok {
					runCmd.Env = append(runCmd.Env, e)
				}
			}

			// Append secrets
			for k, v := range envVars {
				runCmd.Env = append(runCmd.Env, fmt.Sprintf("%s=%s", k, v))
			}

			runErr := runCmd.Run()

			// Build the audit record AFTER the child exits so we have the
			// real ProcessState.ExitCode(). Failures to write the log are
			// non-fatal (logged to stderr) — auditing should never block
			// the actual run.
			recordSession(project, command, cmdArgs, envVars, runCmd)

			if runErr != nil {
				if runCmd.ProcessState != nil {
					if code := runCmd.ProcessState.ExitCode(); code >= 0 {
						os.Exit(code)
					}
				}
				fmt.Fprintf(os.Stderr, "Command execution failed: %v\n", runErr)
				os.Exit(1)
			}
		},
	}

	projectCmd := &cobra.Command{
		Use:   "project",
		Short: "Print the current project's namespace (exit 1 if not in a project)",
		Long: `Walk up from the current directory looking for .rapg.toml. If found,
print the namespace to stdout and exit 0. Otherwise, print nothing and exit 1.

Designed for shell hooks — use 'rapg hook <shell>' to install one.`,
		Run: func(cmd *cobra.Command, args []string) {
			cwd, err := os.Getwd()
			if err != nil {
				os.Exit(1)
			}
			p, _, err := config.Find(cwd)
			if err != nil {
				os.Exit(1)
			}
			fmt.Println(p.Namespace)
		},
	}

	sessionCmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect the rapg run audit log",
	}
	var sessionLimit int
	sessionLogCmd := &cobra.Command{
		Use:   "log",
		Short: "Show recent rapg run sessions (most recent last)",
		Long: `Print the audit trail of rapg run invocations from
~/.rapg/sessions.jsonl. Each line records the command, project namespace,
which env keys were injected (NOT their values), and the exit code.

Default shows the last 20 entries; use --limit to widen.`,
		Run: func(cmd *cobra.Command, args []string) {
			sessions, err := audit.Read(sessionLimit)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading session log: %v\n", err)
				os.Exit(1)
			}
			if len(sessions) == 0 {
				fmt.Fprintln(os.Stderr, "No sessions recorded yet. Run 'rapg run -- <cmd>' to populate the log.")
				return
			}
			printSessions(sessions)
		},
	}
	sessionLogCmd.Flags().IntVar(&sessionLimit, "limit", 20, "max number of recent sessions to show; <=0 means all")
	sessionCmd.AddCommand(sessionLogCmd)

	hookCmd := &cobra.Command{
		Use:   "hook <shell>",
		Short: "Print a shell hook that announces .rapg.toml projects on cd",
		Long: `Print a shell snippet that, when sourced, prints '[rapg] entered project: X'
when you 'cd' into a directory whose .rapg.toml declares a namespace, and
'[rapg] left project: X' when you leave it. Purely informational — does
not auto-inject secrets. Run 'rapg run -- <cmd>' to actually inject.

Install with:

  # zsh (~/.zshrc)
  eval "$(rapg hook zsh)"

  # bash (~/.bashrc)
  eval "$(rapg hook bash)"

  # fish (~/.config/fish/config.fish)
  rapg hook fish | source`,
		ValidArgs: []string{"zsh", "bash", "fish"},
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			snippet, ok := hookSnippets[args[0]]
			if !ok {
				fmt.Fprintf(os.Stderr, "Unsupported shell: %s (zsh|bash|fish)\n", args[0])
				os.Exit(1)
			}
			fmt.Print(snippet)
		},
	}

	rootCmd.AddCommand(genCmd, nukeCmd, exportCmd, runCmd, projectCmd, hookCmd, sessionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func unlockVault() {
	if !core.IsInitialized() {
		fmt.Fprintln(os.Stderr, "Vault not initialized. Run 'rapg' first.")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Master Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	// Immediately move password to a protected buffer and wipe original slice.
	passwordBuffer := memguard.NewBufferFromBytes(bytePassword)
	defer passwordBuffer.Destroy()
	for i := range bytePassword {
		bytePassword[i] = 0
	}

	if err := core.UnlockVault(passwordBuffer.Bytes()); err != nil {
		fmt.Fprintln(os.Stderr, "Invalid password.")
		os.Exit(1)
	}
}

// printSessions writes a tab-aligned, human-readable rendering of the
// session log to stdout. One line per session, ordered oldest to newest.
func printSessions(sessions []audit.Session) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer tw.Flush()
	for _, s := range sessions {
		ns := s.Namespace
		if ns == "" {
			ns = "-"
		}
		keys := strings.Join(s.EnvKeys, ",")
		if keys == "" {
			keys = "-"
		}
		cmdLine := s.Command
		if len(s.Args) > 0 {
			cmdLine += " " + strings.Join(s.Args, " ")
		}
		fmt.Fprintf(tw, "%s\t[%s]\t%s\texit=%d\tkeys: %s\n",
			s.Timestamp.Local().Format("2006-01-02 15:04:05"),
			ns,
			cmdLine,
			s.ExitCode,
			keys,
		)
	}
}

// recordSession appends one entry to ~/.rapg/sessions.jsonl describing the
// command we just ran and which env keys were injected. Failures here are
// non-fatal — auditing must not block the actual run.
func recordSession(project *config.Project, command string, args []string, envVars map[string]string, runCmd *exec.Cmd) {
	keys := make([]string, 0, len(envVars))
	for k := range envVars {
		keys = append(keys, k)
	}

	s := audit.Session{
		Command:  command,
		Args:     args,
		EnvKeys:  keys,
		ExitCode: -1,
	}
	if project != nil {
		s.Namespace = project.Namespace
	}
	if runCmd.ProcessState != nil {
		s.ExitCode = runCmd.ProcessState.ExitCode()
		s.PID = runCmd.ProcessState.Pid()
	}
	if cwd, err := os.Getwd(); err == nil {
		s.Cwd = cwd
	}

	if err := audit.Write(s); err != nil {
		fmt.Fprintf(os.Stderr, "[rapg] warning: failed to write session log: %v\n", err)
	}
}

// loadProject resolves the nearest .rapg.toml from the current working
// directory. Returns nil if none was found (legacy behavior: secrets in the
// global namespace are injected). On parse failure, returns nil and warns
// rather than aborting — a malformed config should not lock the user out.
func loadProject() *config.Project {
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	p, path, err := config.Find(cwd)
	if errors.Is(err, config.ErrNotFound) {
		return nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[rapg] warning: ignoring %s: %v\n", path, err)
		return nil
	}
	fmt.Fprintf(os.Stderr, "[rapg] project: %s (%s)\n", p.Namespace, path)
	return p
}
