# Design: the key cache behind direnv-style auto-injection

Status: **implemented**. `internal/keyagent` and `rapg agent` exist, `rapg run` / `rapg export` consult a running agent, and `rapg hook <shell> --inject` does direnv-style auto-injection on `cd`.

## Why this blocks the roadmap

README's `## Roadmap` has one entry left:

> Direnv-style auto-injection on `cd`, with a TPM / Touch ID / Secure Enclave-backed key cache.

The shell-hook half is easy; `rapg hook <shell>` already fires on `cd` and already knows the project. The blocker is underneath it. Every `rapg` invocation today derives the master key from scratch:

```text
prompt for master password → Argon2id (time=3, memory=128 MiB, threads=4) → 32-byte key → decrypt
```

That is deliberately expensive, and it is fine when you type it once per `rapg run`. It is unusable when the trigger is `cd`. Auto-injection needs the derived key to survive across separate short-lived processes, which is exactly what the vault's design has so far refused to do.

So the question is not "how do we hook `cd`". It is: **where does an already-derived vault key live between two `rapg` processes, without landing on disk and without landing in an environment variable?** The environment is ruled out by the product pitch itself: rapg exists because agents dump their environment into transcripts.

## Threat model

The trust boundary is the user account, the same one the `#nosec` annotations in `run` and `redact` already document. rapg does not defend against a process running as you; it defends against:

1. **Secrets at rest.** A `.env` on disk, a backup, a synced folder, a stolen laptop.
2. **Secrets in an agent's context.** Environment dumps, transcripts, screenshots, bug reports.
3. **Blast radius over time.** A leak of the *master key* is worse than a leak of one secret: it decrypts `~/.rapg/rapg.db` forever, including entries added later, including an offline copy someone took last month. A leak of one secret costs one rotation.

Point 3 is what drives the design below. Anything that hands the raw master key to another process, or writes it somewhere durable, converts a scoped, rotatable incident into an unbounded one.

## Options considered

### A. macOS Keychain item, Touch ID gated

Store the derived key as a generic password with a `SecAccessControl` requiring biometry. Each `cd` triggers Touch ID instead of a password prompt.

Rejected as the base layer. The Keychain is on disk. It is well-encrypted disk, but the *master key* would now be persisted outside the vault it protects, in a store that syncs in some configurations, and the failure mode is permanent (threat 3). It is also macOS only, and rapg ships Linux and Windows builds.

### B. Secure Enclave-wrapped key blob

Generate a non-extractable P-256 key in the Secure Enclave, wrap the vault key with it, keep the wrapped blob in `~/.rapg/`. Unwrapping requires biometry and the blob is useless on another machine.

Cryptographically the strongest option, and the closest to what the roadmap line literally says. Still rejected as the base layer for the same two reasons: it is macOS only, and it makes the master key durable. Worth revisiting as an *optional* hardening once the portable mechanism exists, because it composes: the Enclave can gate access to the agent below rather than replace it.

### C. A local agent process (chosen)

An `ssh-agent`-shaped daemon. It holds the derived key in `memguard`-protected memory, listens on a unix socket in a `0700` directory, and serves requests from processes that pass a peer-credential check. Nothing durable is created. `rapg agent stop`, a TTL, or an idle timeout all destroy the key.

This is the only option that is portable across macOS and Linux, keeps the key off disk entirely, and is revocable in one command. It is also a mechanism users already understand, which matters for a security tool.

## The load-bearing decision: the agent does not hand back the key

The obvious protocol is "client asks, agent returns the 32 bytes". That is the wrong shape, and it is the one detail most worth getting right before any code is wired up.

`ssh-agent` does not return your private key. It signs on your behalf. The same reasoning applies here, and for the same reason as threat 3: if the protocol returns the master key, then any same-uid process that reaches the socket gets permanent, total, unrotatable access to the vault, including its future contents. If the protocol returns *resolved secrets* instead, the same attacker gets exactly the secrets they asked for, which is what they would have got from `rapg run` anyway, and each one is individually rotatable.

So the agent owns `core.SessionKey` and answers a capability request:

```text
client → agent   {"op":"env","namespace":"myapp","inherit_global":false,"keys":["DATABASE_URL"]}
agent  → client  {"ok":true,"env":{"DATABASE_URL":"..."}}
```

The key never crosses the socket. The scoping fields come from the client's `.rapg.toml`, and are a correctness boundary, not a security one: a hostile same-uid process can write its own `.rapg.toml`, and could already do so today. The security boundary is the socket's `0700` directory plus the peer-uid check, both of which stop a *different* user, which is the boundary rapg actually claims.

## What exists

`internal/keyagent`:

- `Server`: listener lifecycle, accept loop, per-connection peer-uid check, absolute TTL and idle timeout, and a `Close` that destroys the key buffer.
- `Client`: dial and round-trip.
- Peer credentials per platform: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on darwin, and an explicit "unsupported" on everything else. `NewServer` refuses to start where peers cannot be identified, so the Windows build stays honest rather than silently insecure.
- Stale-socket recovery, so a crashed agent does not wedge the next start.

`rapg agent start | status | lock | stop`, and `rapg run` / `rapg export` asking a running agent before falling back to the password prompt.

## A correction: `unlockVault()` is the wrong integration point

An earlier draft of this document listed "`unlockVault()` consults the agent first" as the wiring step. That contradicts the decision two sections up, and it took writing the code to notice.

`unlockVault()` exists to populate `core.SessionKey`. The agent will not hand the key over, by design, so it can never satisfy that function. What the agent can satisfy is the *question* `rapg run` and `rapg export` actually ask, which is "what env vars go into this child".

So the integration point is `resolveEnvVars(project)`: ask the agent, and on `ErrNoAgent` or `ErrLocked` fall back to prompting and resolving locally. Commands that genuinely need the key in this process (`rapg redact`, the TUI, `rapg proxy`) still prompt every time, and that is correct rather than a gap. Extending the agent to serve them would mean either handing the key over, which the design rejects, or growing a new capability per command, which is a decision to take one command at a time.

## Settled since the prototype

- **Default TTL: 15-minute idle, 8-hour absolute.** `ssh-agent` defaults to unlimited, which is the wrong default for a tool whose pitch is blast-radius reduction. Both are adjustable with `--idle` and `--ttl` on `rapg agent start`.
- **No auto-start.** `gpg-agent` starts itself on first use, which is convenient, and it means a process holding your master key appears without you having asked for it. `rapg agent start` runs in the foreground; backgrounding it is one `&`, and a key that dies with its terminal is a feature here rather than a limitation.

## How auto-injection turned out

The prediction above was that unsetting on leave would be the hard part, and it was the only part with any real design in it.

`internal/shellenv` renders the transition rather than the state: given what was injected last time and what should be injected now, it emits the `unset` and `export` statements that move the shell from one to the other. The bookkeeping is a single variable, `RAPG_INJECTED`, holding the names currently injected and never the values. Three properties matter:

- **Only names rapg put there are removed.** A variable absent from the tracker is never touched, so the hook cannot eat your own environment.
- **A name being re-exported is not unset first.** Moving between two projects that share a key should not leave a window where it does not exist.
- **Names are validated, values are quoted.** Names go into `unset` and `export` unquoted, where quoting cannot save you, so anything that is not a shell-legal identifier is dropped rather than emitted. Values are vault contents and the output is `eval`'d, so they are single-quoted per shell, and the tests run them through real `bash` and `zsh` to check that backticks, `$(...)`, quotes, newlines and backslashes come back byte-identical.

Two behaviours are deliberate rather than incidental:

- `rapg env` **never prompts**. It runs on every directory change; a password prompt there would be unusable. With no agent or a locked one it cleans up the previous injection and exports nothing, so forgetting to start an agent degrades to the old behaviour rather than to a broken shell.
- **Outside a project, nothing is injected, not even globals.** `rapg run` does inject globals with no project context, but a `rapg run` invocation is scoped to one command and a shell follows you everywhere.

## What is still open

1. Gate the agent behind Touch ID / Secure Enclave on macOS or a TPM on Linux, per option B. This is where the roadmap's "Secure Enclave-backed" phrasing gets honoured, as hardening on top of a portable mechanism rather than as the mechanism.
2. **Windows** has no unix socket story here. Named pipes with a matching SID check are the equivalent. `NewServer` refuses to start where peers cannot be identified, which is honest but not useful, and shipping a weaker implementation to reach parity would be worse than shipping none.
