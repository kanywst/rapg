package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kanywst/rapg/internal/shellenv"
	"github.com/spf13/cobra"
)

// newEnvCmd builds `rapg env`, the statement generator behind direnv-style
// auto-injection. A shell hook evals its output on every `cd`.
func newEnvCmd() *cobra.Command {
	var shell string

	envCmd := &cobra.Command{
		Use:   "env --shell <zsh|bash|fish>",
		Short: "Print shell statements that sync the environment to the current project",
		Long: `Print the export and unset statements that move the current shell from
whatever rapg last injected to what the current directory's project needs.
Intended to be eval'd by the snippet 'rapg hook <shell> --inject' prints.

Reads a running agent only. It never prompts for the master password, because
this runs on every directory change: with no agent, or a locked one, it unsets
whatever it previously injected and exports nothing.

Outside a project it injects nothing at all, including global entries. 'rapg
run' still injects globals when there is no project; a shell that follows you
everywhere is a different matter.`,
		PreRun: openVault,
		Run: func(cmd *cobra.Command, args []string) {
			runEnv(shell)
		},
	}
	envCmd.Flags().StringVar(&shell, "shell", "", "zsh, bash or fish (required)")
	_ = envCmd.MarkFlagRequired("shell")

	return envCmd
}

func runEnv(shell string) {
	previous := strings.Fields(os.Getenv(shellenv.TrackerVar))

	// Only inject inside a project. Outside one this still runs, so that
	// leaving a project takes its secrets with it.
	var env map[string]string
	if project := loadProjectQuiet(); project != nil {
		if fromAgent, ok := envFromAgent(project); ok {
			env = fromAgent
		}
	}

	out, err := shellenv.Render(shell, previous, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
