package main

// hookSnippets maps a shell name to the snippet `rapg hook <shell>` prints.
//
// Each snippet defines an in-shell function that calls `rapg project` to
// detect the nearest .rapg.toml namespace and emits a one-line notice when
// the namespace changes between cwds. RAPG_PROJECT carries the previous
// state across invocations.
//
// These hooks are deliberately informational only. They do not unlock the
// vault, decrypt secrets, or modify the environment. To actually inject
// secrets, run `rapg run -- <cmd>` (which reads the same .rapg.toml).
var hookSnippets = map[string]string{
	"zsh": `# rapg shell hook (zsh)
# Install: eval "$(rapg hook zsh)"
_rapg_chpwd() {
  local current=""
  current="$(rapg project 2>/dev/null)" || current=""
  if [[ "$current" != "${RAPG_PROJECT:-}" ]]; then
    if [[ -n "$current" ]]; then
      print -P "%F{cyan}[rapg]%f entered project: $current  (rapg run -- <cmd> to inject)"
    elif [[ -n "${RAPG_PROJECT:-}" ]]; then
      print -P "%F{cyan}[rapg]%f left project: $RAPG_PROJECT"
    fi
    export RAPG_PROJECT="$current"
  fi
}
typeset -ga chpwd_functions
chpwd_functions+=(_rapg_chpwd)
_rapg_chpwd
`,
	"bash": `# rapg shell hook (bash)
# Install: eval "$(rapg hook bash)"
_rapg_check() {
  local current=""
  current="$(rapg project 2>/dev/null)" || current=""
  if [[ "$current" != "${RAPG_PROJECT:-}" ]]; then
    if [[ -n "$current" ]]; then
      printf '\033[36m[rapg]\033[0m entered project: %s  (rapg run -- <cmd> to inject)\n' "$current"
    elif [[ -n "${RAPG_PROJECT:-}" ]]; then
      printf '\033[36m[rapg]\033[0m left project: %s\n' "$RAPG_PROJECT"
    fi
    export RAPG_PROJECT="$current"
  fi
}
case ";${PROMPT_COMMAND:-};" in
  *";_rapg_check;"*) ;;
  *) PROMPT_COMMAND="_rapg_check;${PROMPT_COMMAND:-}" ;;
esac
`,
	"fish": `# rapg shell hook (fish)
# Install: rapg hook fish | source
function __rapg_check --on-variable PWD --description "rapg project notifier"
  set -l current (rapg project 2>/dev/null; or echo "")
  if test "$current" != "$RAPG_PROJECT"
    if test -n "$current"
      printf '\033[36m[rapg]\033[0m entered project: %s  (rapg run -- <cmd> to inject)\n' "$current"
    else if test -n "$RAPG_PROJECT"
      printf '\033[36m[rapg]\033[0m left project: %s\n' "$RAPG_PROJECT"
    end
    set -gx RAPG_PROJECT "$current"
  end
end
__rapg_check
`,
}

// injectHookSnippets is what `rapg hook <shell> --inject` prints: the
// informational notice plus direnv-style auto-injection.
//
// The heavy lifting is in `rapg env`, which decides what to export and what to
// unset and renders it for the shell. Keeping the snippet thin matters: this
// text runs on every `cd`, it cannot be tested from Go, and any logic in here
// is logic nobody will ever look at again.
//
// `rapg env` never prompts. With no agent running, or a locked one, it unsets
// whatever it previously injected and exports nothing, so the worst case for
// someone who installs this and forgets to start an agent is the behaviour
// they had before.
var injectHookSnippets = map[string]string{
	"zsh": `# rapg shell hook with auto-injection (zsh)
# Install: eval "$(rapg hook zsh --inject)"
# Requires a running agent: rapg agent start &
_rapg_chpwd() {
  local current=""
  current="$(rapg project 2>/dev/null)" || current=""
  if [[ "$current" != "${RAPG_PROJECT:-}" ]]; then
    if [[ -n "$current" ]]; then
      print -P "%F{cyan}[rapg]%f entered project: $current"
    elif [[ -n "${RAPG_PROJECT:-}" ]]; then
      print -P "%F{cyan}[rapg]%f left project: $RAPG_PROJECT"
    fi
    export RAPG_PROJECT="$current"
  fi
  eval "$(rapg env --shell zsh 2>/dev/null)"
}
typeset -ga chpwd_functions
chpwd_functions+=(_rapg_chpwd)
_rapg_chpwd
`,
	"bash": `# rapg shell hook with auto-injection (bash)
# Install: eval "$(rapg hook bash --inject)"
# Requires a running agent: rapg agent start &
_rapg_check() {
  local current=""
  current="$(rapg project 2>/dev/null)" || current=""
  if [[ "$current" != "${RAPG_PROJECT:-}" ]]; then
    if [[ -n "$current" ]]; then
      printf '\033[36m[rapg]\033[0m entered project: %s\n' "$current"
    elif [[ -n "${RAPG_PROJECT:-}" ]]; then
      printf '\033[36m[rapg]\033[0m left project: %s\n' "$RAPG_PROJECT"
    fi
    export RAPG_PROJECT="$current"
  fi
  eval "$(rapg env --shell bash 2>/dev/null)"
}
case ";${PROMPT_COMMAND:-};" in
  *";_rapg_check;"*) ;;
  *) PROMPT_COMMAND="_rapg_check;${PROMPT_COMMAND:-}" ;;
esac
`,
	"fish": `# rapg shell hook with auto-injection (fish)
# Install: rapg hook fish --inject | source
# Requires a running agent: rapg agent start &
function __rapg_check --on-variable PWD --description "rapg project notifier and injector"
  set -l current (rapg project 2>/dev/null; or echo "")
  if test "$current" != "$RAPG_PROJECT"
    if test -n "$current"
      printf '\033[36m[rapg]\033[0m entered project: %s\n' "$current"
    else if test -n "$RAPG_PROJECT"
      printf '\033[36m[rapg]\033[0m left project: %s\n' "$RAPG_PROJECT"
    end
    set -gx RAPG_PROJECT "$current"
  end
  rapg env --shell fish 2>/dev/null | source
end
__rapg_check
`,
}
