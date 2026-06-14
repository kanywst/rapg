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
	// DefaultEnvKey is the vault Env Key that holds this provider's real API
	// key by convention (e.g. "ANTHROPIC_API_KEY"). The CLI uses it to locate
	// the key unless --env-key overrides it.
	DefaultEnvKey() string
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
	case "openai":
		return openai{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider %q (supported: anthropic, openai)", name)
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
func (anthropic) DefaultEnvKey() string   { return "ANTHROPIC_API_KEY" }
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
	}
}

// openai targets api.openai.com. The OpenAI SDKs send the key as
// "Authorization: Bearer <key>" and read OPENAI_BASE_URL + OPENAI_API_KEY.
// OPENAI_BASE_URL must include the /v1 path segment because the SDK appends
// endpoint paths (e.g. /chat/completions) directly to it.
type openai struct{}

func (openai) Name() string            { return "openai" }
func (openai) DefaultEnvKey() string   { return "OPENAI_API_KEY" }
func (openai) UpstreamBaseURL() string { return "https://api.openai.com" }

func (openai) InboundToken(r *http.Request) string {
	return bearer(r)
}

func (openai) SetRealAuth(r *http.Request, realKey string) {
	r.Header.Del("x-api-key")
	r.Header.Set("Authorization", "Bearer "+realKey)
}

func (openai) ChildEnv(listenURL, proxyToken string) map[string]string {
	base := listenURL + "/v1"
	return map[string]string{
		"OPENAI_BASE_URL": base,
		// OPENAI_API_BASE is the legacy variable older SDKs (pre-v1 Python) and
		// some third-party tools still read. Set both for broad compatibility.
		"OPENAI_API_BASE": base,
		"OPENAI_API_KEY":  proxyToken,
	}
}
