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

## Subcommands

| Command | Purpose |
| --- | --- |
| `rapg` | Launch the TUI |
| `rapg run -- <cmd>` | Inject secrets into a child process (respects `.rapg.toml`) |
| `rapg gen [length]` | Generate a cryptographically random password |
| `rapg export` | Print env-tagged secrets as `KEY=value` lines (respects `.rapg.toml`) |
| `rapg project` | Print the current project's namespace; exit 1 if not in a project |
| `rapg hook <shell>` | Print a `cd` notifier snippet for `zsh` / `bash` / `fish` |
| `rapg nuke` | Wipe the local vault after confirmation |

## Roadmap

Next on the agent-leakage track:

1. `rapg redact <file>` — scan a file for vault values and mask them; use this on agent transcripts before sharing.
2. `rapg session log` — audit which command saw which secret and when.
3. `rapg proxy --provider anthropic|openai` (experimental) — local HTTP proxy that holds the real API key, so agents only ever see a short-lived proxy token.
4. Direnv-style auto-injection on `cd`, with a TPM / Touch ID / Secure Enclave-backed key cache.

## Security

| Concern | Implementation |
| --- | --- |
| Master password | Never written to disk; only an Argon2id-derived key hash is stored for verification |
| Key derivation | Argon2id (RFC 9106), defaults `time=3`, `memory=128 MiB`, `threads=4` |
| Encryption | AES-256-GCM (NIST SP 800-38D) with a 12-byte random nonce per record |
| Memory protection | Master key held in a `memguard` LockedBuffer and zeroed on exit |
| At-rest layout | Single SQLite file at `~/.rapg/rapg.db`, directory mode `0700` |

See [`TECH.md`](TECH.md) for the full crypto spec.

## License

MIT — see [LICENSE](LICENSE).
