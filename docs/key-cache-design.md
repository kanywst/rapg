# Design: the key cache behind direnv-style auto-injection

Status: **prototype** (`internal/keyagent` lands in this PR; nothing is wired into the CLI yet).

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

## What is in this PR

`internal/keyagent`, with no CLI surface:

- `Server`: listener lifecycle, accept loop, per-connection peer-uid check, absolute TTL and idle timeout, and a `Close` that destroys the key buffer.
- `Client`: dial and round-trip.
- Peer credentials per platform: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on darwin, and an explicit "unsupported" on everything else so the Windows build stays honest rather than silently insecure.
- Stale-socket recovery, so a crashed agent does not wedge the next start.

Nothing calls it yet. `unlockVault()` is untouched, so behaviour is identical to v0.3.3 for every existing command.

## What comes next, in order

1. `rapg agent start | status | stop`, and `rapg agent unlock` to seed the key.
2. `unlockVault()` consults the agent first and falls back to the password prompt. With no agent running this is a no-op, which is the intended default.
3. `rapg hook <shell>` gains an opt-in auto-injection mode that talks to the agent on `cd`. This is where the roadmap entry is actually satisfied, and it needs its own thinking about how to *unset* variables when you leave a project.
4. Optional: gate the agent's `unlock` behind Touch ID or a TPM, per option B. This is the point where the roadmap's "Secure Enclave-backed" phrasing gets honoured, as hardening on top of a portable mechanism rather than as the mechanism.

## Open questions

- **Default TTL.** `ssh-agent` defaults to unlimited and lets you pass `-t`. For a secret manager whose pitch is blast-radius reduction, unlimited is the wrong default. A 15-minute idle timeout with a 8-hour absolute cap is the current guess in the prototype, but it is a guess.
- **Should the agent auto-start?** Auto-starting on first `rapg run` is convenient and is what `gpg-agent` does. It also means a background process holding your master key appears without you asking for it. Leaning towards explicit start.
- **Unsetting on leave.** Auto-injection that only ever adds variables is a leak of a different kind: you `cd` out of a project and its `DATABASE_URL` is still in your shell. direnv solves this by tracking what it exported. rapg would need the same bookkeeping, and it is not free.
- **Windows.** There is no unix socket story here. Named pipes with a matching SID check are the equivalent, but no Windows user has asked, and shipping a weaker implementation to reach parity would be worse than shipping none.
