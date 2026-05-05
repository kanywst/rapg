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
