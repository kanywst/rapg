# Design: `rapg proxy` — a local short-lived-token gateway for AI agents

Status: **proposed** (design only; no implementation in this PR).

## Why

`rapg run -- <cmd>` injects real API keys into a child's environment. That
keeps keys off disk and out of the parent shell, but the real key still lives
in the agent's process environment. If the agent is subverted by prompt
injection and tricked into running `env` (or reading `/proc/self/environ`),
the real `ANTHROPIC_API_KEY` leaks.

The 2026 consensus is to stop handing agents long-lived provider keys at all:
the real key lives behind a gateway, and the agent only ever sees a
short-lived, scoped token (LiteLLM's "virtual keys", OAuth-style flows). This
document adapts that pattern to rapg's constraints: **single binary,
local-first, no server infrastructure, no team backend.**

## Goal

```text
rapg proxy --provider anthropic -- claude code
```

1. Unlock the vault and load the real provider key into protected memory.
2. Start a localhost-only HTTP listener.
3. Mint a random, per-invocation proxy token held only in memory.
4. Launch the child with the proxy's address + the proxy token injected as
   env (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`).
5. For each inbound request bearing the proxy token, swap in the real key and
   forward to the upstream provider; stream the response back unchanged.
6. When the child exits, stop the listener and zero the key and token.

The real key never enters the child's environment. The only secret the agent
holds is a token that (a) is valid only on `127.0.0.1`, (b) dies when the
process does, and (c) is useless to anyone who exfiltrates it off the machine.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Prompt injection runs `env` / reads environ | Child env holds only the proxy token, not the real key |
| Exfiltrated proxy token reused elsewhere | Token is bound to `127.0.0.1` and to this process lifetime |
| Other local user/process hits the listener | Constant-time token check; bind to loopback only, never `0.0.0.0` |
| Key on disk | Real key stays in the vault (encrypted) and in a `memguard` buffer at runtime |
| Key in logs | Proxy never logs request/response bodies or `Authorization`/`x-api-key` headers |

Out of scope (a localhost dev proxy is not a security boundary against a
fully compromised host): an attacker with code execution as the same user can
already drive the live proxy to make calls. The win is narrower and real —
**the durable secret (the provider key) is never exposed to the agent**, so a
leaked transcript/context/env never contains a reusable credential.

## Architecture

```text
  child (agent)                 rapg proxy (this process)            upstream
  -------------                 -------------------------            --------
  ANTHROPIC_BASE_URL  ──HTTP──▶ 127.0.0.1:PORT
  ANTHROPIC_AUTH_TOKEN          - verify proxy token (constant time)
   = <proxy token>             - strip proxy auth
                                - set real key from memguard  ──TLS──▶ api.anthropic.com
                                - io.Copy response (streaming) ◀──────
```

### Provider abstraction

A `Provider` isolates the per-vendor differences (base URL, which auth header
carries the key, which env vars point an agent at the proxy):

```go
type Provider interface {
    // Name is the --provider value, e.g. "anthropic".
    Name() string
    // UpstreamBaseURL is where verified requests are forwarded.
    UpstreamBaseURL() string
    // SetRealAuth puts the real key on the outbound request in the form this
    // provider expects (Anthropic: x-api-key; OpenAI: Authorization: Bearer).
    SetRealAuth(r *http.Request, realKey string)
    // ChildEnv returns the env vars to inject so an agent talks to the proxy
    // instead of the provider.
    ChildEnv(listenURL, proxyToken string) map[string]string
}
```

| Provider | Upstream | Real-key header | Child env |
| --- | --- | --- | --- |
| `anthropic` | `https://api.anthropic.com` | `x-api-key: <key>` | `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN` |
| `openai` | `https://api.openai.com` | `Authorization: Bearer <key>` | `OPENAI_BASE_URL`, `OPENAI_API_KEY` |

### Which vault entry supplies the key

The provider key is an ordinary vault entry, selected by its `Env Key`:
`--provider anthropic` looks for the entry tagged `ANTHROPIC_API_KEY`,
honoring the same `.rapg.toml` namespace scoping as `rapg run`. A
`--env-key` flag overrides the default mapping when the tag differs.

### Token

- 32 bytes from `crypto/rand`, hex-encoded, minted per invocation.
- Compared with `subtle.ConstantTimeCompare` on every request.
- Held in memory only (alongside the real key in a `memguard` buffer); never
  written to disk or the session log. The audit log records that a proxy ran
  and for which provider/env-key — never the token or key.

### CLI shape

Primary form mirrors `rapg run` (scoped to a child's lifetime — rapg's core
idiom: inject for one process, tear down on exit):

```text
rapg proxy --provider anthropic [--env-key NAME] [--port 0] -- <cmd> [args...]
```

`--port 0` (default) picks a free ephemeral port. A secondary
standalone form (`rapg proxy --provider anthropic` with no `--`, prints the
export lines and stays in the foreground) can come later if there's demand;
the wrapping form is the safe default because the proxy can't outlive the
agent.

## Implementation plan (one PR each)

1. **This PR** — design doc.
2. `internal/proxy`: `Provider` interface + `anthropic` provider + the core
   forwarder (listener, token verification, auth swap, streaming passthrough).
   Tested with `httptest` against a fake upstream; no network, no vault.
3. `cmd/rapg`: wire `rapg proxy --provider anthropic -- <cmd>`, vault unlock,
   key lookup by env-key, child launch with injected env, lifecycle teardown.
   Record the run in the existing session log.
4. `openai` provider + `--env-key` override.
5. Docs: promote from Roadmap to a real README section; update the Security
   table; refresh `demo.tape` if it shows the flow.

## Open questions

- **Streaming:** Anthropic/OpenAI use SSE. Passthrough is a plain `io.Copy`
  with response buffering disabled — verify no proxy-side buffering breaks
  token-by-token streaming.
- **Retries/timeouts:** v1 forwards 1:1 with a generous timeout and no retry
  logic. Cost tracking, rate limiting, and routing are explicitly LiteLLM's
  job, not rapg's.
- **Non-HTTP agents:** only agents that honor a custom base URL can use this.
  That covers Claude Code, OpenAI Agents SDK, and most tools — documented as
  a requirement, not solved in the proxy.
