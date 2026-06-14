package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newTestGateway builds a Gateway whose upstream points at a caller-supplied
// test server instead of the real provider endpoint.
func newTestGateway(t *testing.T, p Provider, realKey, token, upstreamURL string) *Gateway {
	t.Helper()
	g, err := New(p, realKey, token)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	g.upstream = u
	return g
}

func TestGatewaySwapsTokenForRealKey(t *testing.T) {
	const realKey = "sk-REAL-secret-key"
	const token = "proxy-token-abc"

	// Fake upstream asserts it sees the real key and never the proxy token.
	var sawAuthHeader, sawKeyHeader, sawPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthHeader = r.Header.Get("Authorization")
		sawKeyHeader = r.Header.Get("x-api-key")
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	g := newTestGateway(t, anthropic{}, realKey, token, upstream.URL)
	front := httptest.NewServer(g)
	defer front.Close()

	// Agent calls the gateway with the proxy token as a bearer (the
	// ANTHROPIC_AUTH_TOKEN convention).
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", resp.StatusCode, body)
	}
	if string(body) != "upstream-ok" {
		t.Errorf("body = %q, want upstream-ok", body)
	}
	if sawKeyHeader != realKey {
		t.Errorf("upstream x-api-key = %q, want real key %q", sawKeyHeader, realKey)
	}
	if sawAuthHeader != "" {
		t.Errorf("upstream still saw Authorization = %q; proxy token must be stripped", sawAuthHeader)
	}
	if strings.Contains(sawAuthHeader, token) || sawKeyHeader == token {
		t.Error("proxy token leaked to upstream")
	}
	if sawPath != "/v1/messages" {
		t.Errorf("upstream path = %q, want /v1/messages", sawPath)
	}
}

func TestGatewayPreservesEscapedPath(t *testing.T) {
	const token = "tok"
	var sawRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequestURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	g := newTestGateway(t, anthropic{}, "real", token, upstream.URL)
	front := httptest.NewServer(g)
	defer front.Close()

	// %2F must reach the upstream still escaped, not decoded to a slash.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/models/a%2Fb", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if !strings.Contains(sawRequestURI, "%2F") {
		t.Errorf("upstream RequestURI = %q, want it to keep the escaped %%2F", sawRequestURI)
	}
}

func TestGatewayRejectsBadToken(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()

	g := newTestGateway(t, anthropic{}, "real", "good-token", upstream.URL)
	front := httptest.NewServer(g)
	defer front.Close()

	cases := map[string]string{
		"wrong token": "Bearer wrong-token",
		"no auth":     "",
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/models", nil)
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
	if upstreamHit {
		t.Error("upstream was reached despite an invalid proxy token")
	}
}

func TestGatewayAcceptsXAPIKeyToken(t *testing.T) {
	const token = "tok-via-xapikey"
	var sawKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	g := newTestGateway(t, anthropic{}, "REALKEY", token, upstream.URL)
	front := httptest.NewServer(g)
	defer front.Close()

	// ANTHROPIC_API_KEY convention: the proxy token arrives as x-api-key.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/models", nil)
	req.Header.Set("x-api-key", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawKey != "REALKEY" {
		t.Errorf("upstream x-api-key = %q, want REALKEY (real key must replace the token)", sawKey)
	}
}

func TestOpenAISwapsTokenForRealKey(t *testing.T) {
	const realKey = "sk-openai-REAL"
	const token = "openai-proxy-token"

	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	g := newTestGateway(t, openai{}, realKey, token, upstream.URL)
	front := httptest.NewServer(g)
	defer front.Close()

	// OpenAI SDK convention: token arrives as Authorization: Bearer.
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/chat/completions", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if sawAuth != "Bearer "+realKey {
		t.Errorf("upstream Authorization = %q, want bearer real key", sawAuth)
	}
	if strings.Contains(sawAuth, token) {
		t.Error("proxy token leaked to upstream")
	}
}

func TestOpenAIChildEnv(t *testing.T) {
	env := openai{}.ChildEnv("http://127.0.0.1:7777", "TOK")
	// Base URL must carry /v1 — the SDK appends endpoint paths to it.
	if env["OPENAI_BASE_URL"] != "http://127.0.0.1:7777/v1" {
		t.Errorf("OPENAI_BASE_URL = %q, want .../v1", env["OPENAI_BASE_URL"])
	}
	if env["OPENAI_API_KEY"] != "TOK" {
		t.Errorf("OPENAI_API_KEY = %q", env["OPENAI_API_KEY"])
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken failed: %v", err)
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length = %d, want 64 hex chars", len(a))
	}
	b, _ := NewToken()
	if a == b {
		t.Error("two NewToken calls returned the same token")
	}
}

func TestAnthropicChildEnv(t *testing.T) {
	env := anthropic{}.ChildEnv("http://127.0.0.1:7777", "TOK")
	if env["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:7777" {
		t.Errorf("ANTHROPIC_BASE_URL = %q", env["ANTHROPIC_BASE_URL"])
	}
	if env["ANTHROPIC_AUTH_TOKEN"] != "TOK" {
		t.Errorf("ANTHROPIC_AUTH_TOKEN = %q", env["ANTHROPIC_AUTH_TOKEN"])
	}
}

func TestLookup(t *testing.T) {
	p, err := Lookup("anthropic")
	if err != nil {
		t.Errorf("Lookup(anthropic) error: %v", err)
	}
	if got := p.DefaultEnvKey(); got != "ANTHROPIC_API_KEY" {
		t.Errorf("anthropic DefaultEnvKey = %q, want ANTHROPIC_API_KEY", got)
	}
	if _, err := Lookup("nope"); err == nil {
		t.Error("Lookup(nope) should return an error")
	}
}
