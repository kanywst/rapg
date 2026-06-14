# rapg

Single-binary, local-first secret manager built for the AI-agent era.

[![Go Version](https://img.shields.io/github/go-mod/go-version/kanywst/rapg?style=flat-square)](https://go.dev/) [![Build Status](https://img.shields.io/github/actions/workflow/status/kanywst/rapg/test.yml?branch=master&style=flat-square)](https://github.com/kanywst/rapg/actions) [![License](https://img.shields.io/github/license/kanywst/rapg?style=flat-square)](LICENSE)

![Demo](demo.gif)

## The problem in 2026

You hand `ANTHROPIC_API_KEY` to Claude Code. You hand `AWS_SECRET_ACCESS_KEY` to your Cursor agent. You hand a database URL to whatever shell snippet your LLM just generated.

Three things go wrong:

1. The agent's transcript and context window now contain your secret. Logs persist, screenshots happen, transcripts get pasted into bug reports.
2. `.env` files keep that secret in plaintext on disk, and someone always commits one by accident.
3. Existing managers (1Password, Bitwarden) solve team sharing — they do not solve agent leakage.

`rapg` is a small Go binary that keeps your dev secrets in a locally encrypted vault and injects them into child processes, including AI agents, without ever writing them to disk.

## Install

Requires Go 1.25 or newer.

```bash
go install github.com/kanywst/rapg/cmd/rapg@latest
```

## Quick start

First run sets a master password (minimum 12 chars, strong complexity):

```bash
rapg
```

In the TUI, press `n` to add a secret. Fill in `Service`, `Username`, `Password`, and the `Env Key` field, for example `ANTHROPIC_API_KEY`.

Inject those secrets into any child process:

```bash
rapg run -- claude code
rapg run -- npm run dev
rapg run -- python script.py
```

The child sees `ANTHROPIC_API_KEY` and any other `Env Key`-tagged secret in its environment. Your `.env` file stays out of git, your real keys stay off disk, and the parent shell never holds them in scrollback.

A minimal verification script lives at `examples/main.py`:

```bash
rapg run -- python examples/main.py
```

### Wrapping MCP servers

An MCP server is just another child process that needs credentials — and 2026 security guidance flags MCP servers as a dangerous single point of credential aggregation. Wrap one with `rapg run` so its token comes from the vault instead of a `.env` file on disk:

```bash
# any MCP server that reads its token from the environment
rapg run -- npx -y @modelcontextprotocol/server-github
```

The server reads its credential (e.g. a GitHub PAT) from the environment you tagged with an `Env Key`; the value never lands in a config file, the shell history, or — since `inherit_global` defaults to `false` — any other project's context.

## TUI keys

| Key | Action |
| --- | --- |
| `j` / `k` / arrows | Navigate the entry list |
| `n` | New entry (Service, Username, Password, TOTP, Namespace, Env Key, Notes) |
| `enter` / `space` | Open detail view |
| `enter` (in detail) | Copy password to clipboard |
| `ctrl+t` | Copy current TOTP code |
| `d` | Delete the selected entry |
| `q` | Quit |

## Project-scoped secrets (`.rapg.toml`)

Drop a `.rapg.toml` at your repository root to scope which secrets `rapg run` and `rapg export` see:

```toml
namespace = "myapp"

# Optional. Three states:
#   - omitted               → no whitelist, inject every env-tagged
#                             secret in the namespace
#   - keys = []             → explicit deny-all (project recognized,
#                             but no env vars injected)
#   - keys = ["A", "B"]     → standard whitelist
keys = ["DATABASE_URL", "ANTHROPIC_API_KEY"]

# Optional. Default false. When true, entries with empty Namespace
# (the 'global' bucket) are also injected. Project entries override
# global on env-key collision.
# inherit_global = true
```

When you add a secret in the TUI, fill in the `Namespace` field with the same value (e.g., `myapp`). Then:

```bash
cd ~/code/myapp
rapg run -- claude code
# [rapg] project: myapp (/Users/me/code/myapp/.rapg.toml)
# child sees only myapp's DATABASE_URL and ANTHROPIC_API_KEY
```

Resolution rules:

- Discovery walks up from `cwd` to `/`. The first `.rapg.toml` wins.
- No `.rapg.toml` found → only entries with empty Namespace ("global") are injected.
- A namespaced entry is invisible outside its project unless the project opts in via `inherit_global = true` — which lets shared utility secrets (e.g. `GITHUB_TOKEN`) live once in the global bucket and be borrowed by projects that ask for them. Project entries always win on key collision.
- Same `Service` / `Username` pair can exist across multiple namespaces.

## Shell hook (informational)

`rapg hook <shell>` prints a snippet that announces project entry/exit on `cd`. It does **not** auto-inject secrets — run `rapg run -- <cmd>` for that. Auto-injection (direnv-style) is planned for v4.1; doing it safely without an in-shell key cache is a separate problem.

```bash
# zsh: ~/.zshrc
eval "$(rapg hook zsh)"

# bash: ~/.bashrc
eval "$(rapg hook bash)"

# fish: ~/.config/fish/config.fish
rapg hook fish | source
```

After installing, `cd` between project directories prints:

```text
[rapg] entered project: myapp  (rapg run -- <cmd> to inject)
[rapg] left project: myapp
```

## Transcript hygiene (`rapg redact`)

Before pasting an agent transcript into a bug report, scrub vault values from it:

```bash
rapg redact ~/.claude/transcripts/today.jsonl > redacted.jsonl
# or, against the clipboard:
pbpaste | rapg redact - | pbcopy
```

Each occurrence of a vault `Password` becomes `[REDACTED:<env_key>]` (or `[REDACTED:<service>/<username>]` if the entry has no env key). Values shorter than 8 characters are skipped to avoid false positives. The match count is reported on stderr so it doesn't contaminate the redacted output stream.

Scope is the whole vault, regardless of `.rapg.toml` — when checking a transcript, you want maximum coverage, not project boundaries.

## Audit log (`rapg session log`)

Every `rapg run -- <cmd>` appends one line to `~/.rapg/sessions.jsonl` recording the command, project namespace, env keys injected (**not** their values), exit code, pid, and cwd. Read the trail back:

```bash
rapg session log
# 2026-05-05 14:30:12  [myapp]  claude code --print  exit=0  keys: ANTHROPIC_API_KEY,DB_URL
# 2026-05-05 14:32:05  [-]       npm run dev          exit=0  keys: -

rapg session log --limit 100
```

The log is plaintext metadata at mode `0600`. To wipe it, just `rm ~/.rapg/sessions.jsonl` — `rapg run` will recreate it on the next invocation.

## Subcommands

| Command | Purpose |
| --- | --- |
| `rapg` | Launch the TUI |
| `rapg run -- <cmd>` | Inject secrets into a child process (respects `.rapg.toml`, records to session log) |
| `rapg gen [length]` | Generate a cryptographically random password |
| `rapg export` | Print env-tagged secrets as `KEY=value` lines (respects `.rapg.toml`) |
| `rapg redact <file\|->` | Mask vault values in a file or stdin; output to stdout |
| `rapg session log` | Show recent `rapg run` sessions from `~/.rapg/sessions.jsonl` |
| `rapg project` | Print the current project's namespace; exit 1 if not in a project |
| `rapg hook <shell>` | Print a `cd` notifier snippet for `zsh` / `bash` / `fish` |
| `rapg nuke` | Wipe the local vault after confirmation |

## Roadmap

Next on the agent-leakage track:

1. `rapg proxy --provider anthropic|openai` (experimental) — local HTTP proxy that holds the real API key, so agents only ever see a short-lived proxy token.
2. Direnv-style auto-injection on `cd`, with a TPM / Touch ID / Secure Enclave-backed key cache.

## Security

| Concern | Implementation |
| --- | --- |
| Master password | Never written to disk; only an Argon2id-derived key hash is stored for verification |
| Key derivation | Argon2id (RFC 9106), defaults `time=3`, `memory=128 MiB`, `threads=4` |
| Encryption | AES-256-GCM (NIST SP 800-38D) with a 12-byte random nonce per record |
| Memory protection | Master key held in a `memguard` LockedBuffer and zeroed on exit |
| At-rest layout | Single SQLite file at `~/.rapg/rapg.db`, directory mode `0700` |
| Prompt-injection blast radius | Secrets go into the child's environment, never the prompt or context window; `rapg redact` scrubs vault values from transcripts before you share them |

## Scope

rapg secures the **secret boundary on your local dev machine** — keeping real keys off disk and out of agent transcripts. It is deliberately not a production identity platform: per-agent non-human identities, workload identity federation, and automated provider-side rotation belong in your cloud IAM or a server-side vault (HashiCorp Vault, AWS Secrets Manager). rapg is the local-first complement to those, not a replacement.

## License

MIT — see [LICENSE](LICENSE).
