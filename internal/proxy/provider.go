// Package proxy implements a localhost-only gateway that holds a real
// provider API key and hands AI agents a short-lived, loopback-bound proxy
// token instead. The agent talks to the gateway with the token; the gateway
// swaps in the real key and forwards to the upstream provider. The real key
// never enters the agent's environment, so a prompt-injected agent that reads
// its own env leaks only a token that dies with the process and is useless
// off-machine.
//
// See docs/proxy-design.md for the threat model and rationale.
package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// Provider isolates the per-vendor differences: where to forward, how the
// real key is carried on the outbound request, how the agent's inbound proxy
// token is read, and which env vars point an agent at the gateway.
type Provider interface {
	// Name is the --provider value, e.g. "anthropic".
	Name() string
	// UpstreamBaseURL is where verified requests are forwarded.
	UpstreamBaseURL() string
	// InboundToken extracts the proxy token the agent sent on the request,
	// or "" if absent.
	InboundToken(r *http.Request) string
	// SetRealAuth puts the real key on the outbound request in the form this
	// provider expects, and removes any proxy-token auth headers.
	SetRealAuth(r *http.Request, realKey string)
	// ChildEnv returns the env vars to inject so an agent talks to the
	// gateway instead of the provider directly.
	ChildEnv(listenURL, proxyToken string) map[string]string
}

// Lookup returns the Provider for a --provider value, or an error naming the
// supported set.
func Lookup(name string) (Provider, error) {
	switch name {
	case "anthropic":
		return anthropic{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider %q (supported: anthropic)", name)
	}
}

// bearer pulls the token out of an "Authorization: Bearer <token>" header,
// returning "" when the header is missing or not a bearer scheme.
func bearer(r *http.Request) string {
	const prefix = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return v[len(prefix):]
	}
	return ""
}

// anthropic targets api.anthropic.com. Claude Code with ANTHROPIC_AUTH_TOKEN
// sends the token as "Authorization: Bearer <token>"; with ANTHROPIC_API_KEY
// it sends "x-api-key: <token>". We accept either so both env conventions
// work. The real key is sent upstream as x-api-key.
type anthropic struct{}

func (anthropic) Name() string            { return "anthropic" }
func (anthropic) UpstreamBaseURL() string { return "https://api.anthropic.com" }

func (anthropic) InboundToken(r *http.Request) string {
	if t := bearer(r); t != "" {
		return t
	}
	return r.Header.Get("x-api-key")
}

func (anthropic) SetRealAuth(r *http.Request, realKey string) {
	// Strip whatever proxy-token auth the agent sent, then set the real key
	// the way Anthropic expects it.
	r.Header.Del("Authorization")
	r.Header.Set("x-api-key", realKey)
}

func (anthropic) ChildEnv(listenURL, proxyToken string) map[string]string {
	return map[string]string{
		"ANTHROPIC_BASE_URL":   listenURL,
		"ANTHROPIC_AUTH_TOKEN": proxyToken,
		// Also set ANTHROPIC_API_KEY so the official SDKs (Python, TS, Go),
		// which ignore ANTHROPIC_AUTH_TOKEN, still authenticate. They send it
		// as x-api-key, which InboundToken accepts. Since the proxy strips the
		// real key from the child env, this is the token, not the real key.
		"ANTHROPIC_API_KEY": proxyToken,
	}
}
