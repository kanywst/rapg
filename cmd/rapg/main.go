package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/awnumar/memguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/kanywst/rapg/internal/audit"
	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/core"
	"github.com/kanywst/rapg/internal/proxy"
	"github.com/kanywst/rapg/internal/redact"
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

	redactCmd := &cobra.Command{
		Use:   "redact <file|->",
		Short: "Mask vault values appearing in a file (use on agent transcripts before sharing)",
		Long: `Read <file> (or stdin if '-') and replace every occurrence of any vault
secret value with '[REDACTED:<label>]'. Output goes to stdout. Match count
is reported to stderr.

Scans every entry in the vault, regardless of namespace or .rapg.toml — the
goal is maximum coverage when checking what a transcript might have leaked.
Values shorter than 8 characters are skipped to avoid false positives like
masking the word "test".

Examples:

    rapg redact ~/.claude/transcripts/today.jsonl > redacted.jsonl
    pbpaste | rapg redact - | pbcopy`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runRedact(args[0])
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
			if err := printSessions(sessions); err != nil {
				// Most likely a broken pipe (e.g. piped to `head`).
				// Exit quietly with non-zero so callers can detect it
				// without flooding stderr.
				os.Exit(1)
			}
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

	var proxyProvider, proxyEnvKey string
	var proxyPort int
	proxyCmd := &cobra.Command{
		Use:   "proxy --provider <name> -- <command>",
		Short: "Run a command behind a localhost gateway that holds the real API key",
		Long: `Start a loopback-only HTTP gateway that holds a provider's real API key and
inject a short-lived proxy token into a child process instead. The child (an
AI agent) talks to the gateway with the token; the gateway swaps in the real
key and forwards to the upstream provider. The real key never enters the
child's environment, so a prompt-injected agent that reads its own env leaks
only a token that dies with this process and is useless off-machine.

The key is an ordinary vault entry, located by its Env Key (default: the
provider's standard key, e.g. ANTHROPIC_API_KEY), honoring .rapg.toml scoping.

Example:

    rapg proxy --provider anthropic -- claude code`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			runProxy(proxyProvider, proxyEnvKey, proxyPort, args)
		},
	}
	proxyCmd.Flags().StringVar(&proxyProvider, "provider", "", "API provider to proxy (anthropic)")
	proxyCmd.Flags().StringVar(&proxyEnvKey, "env-key", "", "vault Env Key holding the real API key (default: the provider's standard key)")
	proxyCmd.Flags().IntVar(&proxyPort, "port", 0, "localhost port to listen on (0 = ephemeral)")
	_ = proxyCmd.MarkFlagRequired("provider")

	rootCmd.AddCommand(genCmd, nukeCmd, exportCmd, runCmd, projectCmd, hookCmd, sessionCmd, redactCmd, proxyCmd)

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

// runRedact executes 'rapg redact <file|->'. It unlocks the vault, builds
// a list of (value, label) pairs from every entry that has a non-empty
// password, runs the redactor, and writes the masked output to stdout.
// Match count goes to stderr so it never contaminates the output stream.
func runRedact(target string) {
	unlockVault()

	entries, err := core.ListEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing entries: %v\n", err)
		os.Exit(1)
	}

	var (
		secrets []redact.Secret
		skipped int
	)
	for _, e := range entries {
		secret, err := core.GetEntry(e)
		if err != nil {
			// Decryption failure on a real entry is meaningful: the
			// entry's value is in the vault but we couldn't read it,
			// so anything matching it in the input is NOT going to
			// get redacted. Surface it loudly so the user doesn't
			// trust the output blindly.
			fmt.Fprintf(os.Stderr, "[rapg] warning: skipping entry %q: %v\n", e.Service+"/"+e.Username, err)
			skipped++
			continue
		}
		if secret.Password == "" {
			continue
		}
		label := secret.EnvKey
		if label == "" {
			label = e.Service + "/" + e.Username
		}
		secrets = append(secrets, redact.Secret{Value: secret.Password, Label: label})
	}

	var input []byte
	if target == "-" {
		input, err = io.ReadAll(os.Stdin)
	} else {
		// #nosec G304 -- target is the file the user explicitly asked
		// rapg to redact; the user IS the trust boundary in a CLI tool.
		input, err = os.ReadFile(target)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	out, n := redact.Redact(string(input), secrets)
	fmt.Print(out)
	fmt.Fprintf(os.Stderr, "[rapg] redacted %d distinct value(s) from %d candidate(s)\n", n, len(secrets))
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "[rapg] WARNING: %d entr%s could not be decrypted; output may still contain their values\n",
			skipped, plural(skipped, "y", "ies"))
	}
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// printSessions writes a tab-aligned, human-readable rendering of the
// session log to stdout. One line per session, ordered oldest to newest.
// Returns any error from writing to stdout (typically a broken pipe when
// piped through `head` etc.) or from the tabwriter flush.
func printSessions(sessions []audit.Session) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
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
		if _, err := fmt.Fprintf(tw, "%s\t[%s]\t%s\texit=%d\tkeys: %s\n",
			s.Timestamp.Local().Format("2006-01-02 15:04:05"),
			ns,
			cmdLine,
			s.ExitCode,
			keys,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
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

// runProxy starts a localhost gateway holding the provider's real API key and
// runs args[0] with a short-lived proxy token injected via the provider's
// child env. The real key never enters the child's environment — that is the
// whole point versus 'rapg run'. The proxy is bound to the child's lifetime:
// when the child exits, the listener goes down with the process.
func runProxy(providerName, envKeyOverride string, port int, args []string) {
	prov, err := proxy.Lookup(providerName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	envKey := envKeyOverride
	if envKey == "" {
		envKey = prov.DefaultEnvKey()
	}

	project := loadProject()
	unlockVault()

	envVars, err := core.GetEnvVars(project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting env vars: %v\n", err)
		os.Exit(1)
	}
	realKey, ok := envVars[envKey]
	if !ok {
		fmt.Fprintf(os.Stderr, "No vault entry tagged Env Key %q is in scope. Add one (or pass --env-key).\n", envKey)
		os.Exit(1)
	}

	token, err := proxy.NewToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error minting proxy token: %v\n", err)
		os.Exit(1)
	}
	gw, err := proxy.New(prov, realKey, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating proxy: %v\n", err)
		os.Exit(1)
	}

	// Loopback only — never 0.0.0.0. The proxy token is the only thing
	// guarding the listener, and it is valid solely on this host for this
	// process.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error binding localhost port: %v\n", err)
		os.Exit(1)
	}
	srv := &http.Server{
		Handler: gw,
		// Bound request-header reads (Slowloris guard). This caps header
		// reading only; it does not limit streamed SSE responses.
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "[rapg] proxy server error: %v\n", serveErr)
		}
	}()
	defer func() { _ = srv.Close() }()

	listenURL := "http://" + ln.Addr().String()
	fmt.Fprintf(os.Stderr, "[rapg] proxy: %s -> %s (key from %s); child sees a short-lived token, not the key\n",
		listenURL, prov.UpstreamBaseURL(), envKey)

	childEnv := prov.ChildEnv(listenURL, token)

	command := args[0]
	cmdArgs := args[1:]
	// #nosec G204 -- the command is supplied by the user invoking the CLI; the
	// user is the trust boundary, same as 'rapg run'.
	runCmd := exec.Command(command, cmdArgs...)
	runCmd.Stdin = os.Stdin
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	// Inject the same scoped secrets 'rapg run' would, EXCEPT the real
	// provider key — the agent reaches that only through the proxy token. Then
	// layer the provider's base-URL/token env on top so the SDK points at the
	// gateway.
	injected := make(map[string]string, len(envVars)+len(childEnv))
	for k, v := range envVars {
		if k != envKey {
			injected[k] = v
		}
	}
	maps.Copy(injected, childEnv)

	// Strip the real provider key if it's already exported in the parent shell
	// — otherwise it would pass straight through to the child and defeat the
	// whole point of the proxy. Drop the provider's default key too, in case
	// --env-key points elsewhere but the standard var is also set.
	runCmd.Env = childEnviron(os.Environ(), injected, envKey, prov.DefaultEnvKey())

	runErr := runCmd.Run()

	// Record the session: every scoped secret key in play (NOT their values),
	// matching 'rapg run'. envKey is the proxied provider key.
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
}

// childEnviron builds a child process environment from the parent's `environ`
// (os.Environ() form: "KEY=value"), with `override` entries set last so they
// win, and any key in `strip` removed entirely. strip is how `rapg proxy`
// guarantees the real provider key never reaches the child even when the
// parent shell already exports it.
func childEnviron(environ []string, override map[string]string, strip ...string) []string {
	stripped := make(map[string]bool, len(strip))
	for _, k := range strip {
		if k != "" {
			stripped[k] = true
		}
	}
	out := make([]string, 0, len(environ)+len(override))
	for _, e := range environ {
		key := strings.SplitN(e, "=", 2)[0]
		if stripped[key] {
			continue
		}
		if _, overridden := override[key]; overridden {
			continue
		}
		out = append(out, e)
	}
	for k, v := range override {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}
