package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/awnumar/memguard"
	tea "github.com/charmbracelet/bubbletea"
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
			unlockVault()

			envVars, err := core.GetEnvVars()
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
			unlockVault()

			envVars, err := core.GetEnvVars()
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

			if err := runCmd.Run(); err != nil {
				// ProcessState.ExitCode() is portable across Linux/macOS/Windows
				// and returns -1 if the process did not exit normally.
				if runCmd.ProcessState != nil {
					if code := runCmd.ProcessState.ExitCode(); code >= 0 {
						os.Exit(code)
					}
				}
				fmt.Fprintf(os.Stderr, "Command execution failed: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// New: Import Command
	importCmd := &cobra.Command{
		Use:   "import [csv_file]",
		Short: "Import passwords from a CSV file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			file, err := os.Open(args[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
				os.Exit(1)
			}
			defer file.Close()

			unlockVault()

			count, err := core.ImportCSV(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Successfully imported %d passwords.\n", count)
		},
	}

	// New: Audit Command
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Check for reused passwords",
		Run: func(cmd *cobra.Command, args []string) {
			unlockVault()

			results, err := core.AuditPasswords()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
				os.Exit(1)
			}

			if len(results) == 0 {
				fmt.Println("✅ No reused passwords found. Good job!")
				return
			}

			fmt.Println("⚠️  Reuse Detected! The following passwords are used in multiple places:")
			for _, r := range results {
				fmt.Printf("\nPassword used %d times:\n", r.Count)
				for _, svc := range r.Services {
					fmt.Printf("  - %s\n", svc)
				}
			}
			fmt.Println("\nTip: Use 'rapg gen' to replace them with unique passwords.")
		},
	}

	rootCmd.AddCommand(genCmd, nukeCmd, exportCmd, runCmd, importCmd, auditCmd)

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
