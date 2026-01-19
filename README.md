<div align="center">

# Rapg

### The Developer-First Secret Manager

[![Go Version](https://img.shields.io/github/go-mod/go-version/kanywst/rapg?style=flat-square)](https://go.dev/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/kanywst/rapg/test.yml?branch=main&style=flat-square)](https://github.com/kanywst/rapg/actions)
[![License](https://img.shields.io/github/license/kanywst/rapg?style=flat-square)](LICENSE)

**Stop sharing `.env` files over Slack.**<br>
**Stop keeping cleartext credentials on your disk.**

![Demo](demo.gif)

</div>

---

## What is Rapg?

**Rapg** (Rapid/pg) is a secure, TUI-based secret manager designed specifically for developers who live in the terminal. It allows you to store credentials securely and inject them directly into your development processes without ever writing `.env` files to disk.

## Installation

Required: Go 1.25+

```bash
go install github.com/kanywst/rapg/cmd/rapg@latest
```

## Usage Guide

### 1. Initialization

Run `rapg` for the first time to initialize your secure vault.

```bash
rapg
```

You will be prompted to **Create a Master Password**.
> **Note:** Choose a strong password (min 12 chars). This password is used to derive your encryption key and is **never stored**. If you lose it, your data is lost forever.

### 2. Managing Secrets (TUI)

Once unlocked, you are in the TUI mode.

- **Navigation**: Use `j`/`k` or `Up`/`Down` arrows.
- **Add Secret**: Press `n`.
  - **Service/Username**: Identifiers for your secret.
  - **Password**: Leave empty to auto-generate a secure random password.
  - **TOTP Secret**: (Optional) Enter your 2FA seed key to generate codes.
  - **Env Key**: (Important) The environment variable name (e.g., `DATABASE_PASSWORD`) used for injection.
- **View Details**: Press `Enter` or `Space` to decrypt and view a secret.
- **Copy Password**: Press `Enter` on the detail view.
- **Copy TOTP**: Press `Ctrl+t` to generate and copy the 2FA code.
- **Delete**: Press `d` to delete the selected entry.
- **Quit**: Press `q`.

### 3. Process Injection (`rapg run`)

This is the core feature. Instead of creating a `.env` file, wrap your command with `rapg run`.

Rapg will decrypt secrets that have an **Env Key** set and inject them into the child process environment.

```bash
# Inject secrets into your Node.js app
rapg run -- npm start

# Inject into Python script
rapg run -- python main.py

# Or any other command
rapg run -- printenv DATABASE_PASSWORD
```

#### Verify with Example Script

We included a simple Python script in `examples/main.py` to test the injection.

1. Add a secret in Rapg with Env Key `DATABASE_PASSWORD`.
2. Run the script:

```bash
rapg run -- python examples/main.py
```

> **Security:** The secrets exist only in the memory of the process. They are never written to disk.

### 4. Advanced Tools

#### Security Audit

Check if you are reusing passwords across different services.

```bash
rapg audit
```

#### Import/Export

Migrate from other tools or generate a `.env` file if absolutely necessary (e.g., for Docker).

```bash
# Import from CSV
rapg import passwords.csv

# Export to stdout (can redirect to .env)
rapg export > .env.local
```

## Security Architecture

- **Zero-Knowledge**: Master password is never stored.
- **Encryption**: AES-256-GCM.
- **Key Derivation**: Argon2id (RFC 9106).
- **Memory Safety**: Uses `memguard` to protect keys in memory.

## License

MIT License - see [LICENSE](LICENSE) for details.
