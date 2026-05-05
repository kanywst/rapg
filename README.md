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
| `n` | New entry |
| `enter` / `space` | Open detail view |
| `enter` (in detail) | Copy password to clipboard |
| `ctrl+t` | Copy current TOTP code |
| `d` | Delete the selected entry |
| `q` | Quit |

## Subcommands

| Command | Purpose |
| --- | --- |
| `rapg` | Launch the TUI |
| `rapg run -- <cmd>` | Inject secrets into a child process |
| `rapg gen [length]` | Generate a cryptographically random password |
| `rapg export` | Print env-tagged secrets as `KEY=value` lines (use sparingly: Docker, CI debugging) |
| `rapg nuke` | Wipe the local vault after confirmation |

## Roadmap

The next milestones lean into the agent-leakage problem:

1. `.rapg.toml` per-project config and a shell hook so `cd project/` auto-loads the right secrets.
2. `rapg redact <file>` — scan a file for vault values and mask them; use this on agent transcripts before sharing.
3. `rapg session log` — audit which command saw which secret and when.
4. `rapg proxy --provider anthropic|openai` (experimental) — local HTTP proxy that holds the real API key, so agents only ever see a short-lived proxy token.

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
