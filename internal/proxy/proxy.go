package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// NewToken mints a random 32-byte proxy token, hex-encoded. It is minted per
// invocation, held only in memory, and never written to disk.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Gateway is the localhost forwarder. It verifies the agent's proxy token,
// swaps in the real provider key, and streams the upstream response back.
//
// realKey lives here in memory for the gateway's lifetime — the proxy must
// hold the key to use it. The win over `rapg run` is that the key is in THIS
// process, not the agent's, so the agent never sees a reusable credential.
type Gateway struct {
	provider Provider
	realKey  string
	token    string
	upstream *url.URL
	client   *http.Client
}

// New builds a Gateway for the given provider, real key, and proxy token.
func New(p Provider, realKey, token string) (*Gateway, error) {
	base, err := url.Parse(p.UpstreamBaseURL())
	if err != nil {
		return nil, fmt.Errorf("proxy: bad upstream URL for %s: %w", p.Name(), err)
	}
	return &Gateway{
		provider: p,
		realKey:  realKey,
		token:    token,
		upstream: base,
		client:   &http.Client{},
	}, nil
}

// hopByHop headers must not be forwarded between connections (RFC 7230 6.1).
var hopByHop = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Verify the proxy token in constant time. A mismatch (or an absent
	//    token) is rejected before we touch the real key or the upstream.
	got := g.provider.InboundToken(r)
	if subtle.ConstantTimeCompare([]byte(got), []byte(g.token)) != 1 {
		http.Error(w, "invalid or missing proxy token", http.StatusUnauthorized)
		return
	}

	// 2. Build the outbound request against the upstream base.
	out := *g.upstream
	out.Path = singleJoiningSlash(g.upstream.Path, r.URL.Path)
	out.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, out.String(), r.Body)
	if err != nil {
		http.Error(w, "proxy: could not build upstream request", http.StatusInternalServerError)
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Host = g.upstream.Host
	req.ContentLength = r.ContentLength

	// 3. Swap the agent's proxy token for the real key.
	g.provider.SetRealAuth(req, g.realKey)

	// 4. Forward and stream the response back unchanged.
	// #nosec G704 -- Not an open SSRF. The destination scheme+host are pinned
	// to the provider's constant upstream (e.g. api.anthropic.com): `out` is a
	// copy of g.upstream and only Path/RawQuery are taken from the agent's
	// request. Forwarding the agent's path/query to a fixed host is exactly
	// what a transparent API gateway does; the agent cannot redirect to an
	// arbitrary host.
	resp, err := g.client.Do(req)
	if err != nil {
		http.Error(w, "proxy: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	flushingCopy(w, resp.Body)
}

// copyHeaders copies non-hop-by-hop headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// flushingCopy streams src to w, flushing after each chunk so server-sent
// events (Anthropic/OpenAI token streaming) reach the agent immediately
// rather than being buffered until the response ends.
func flushingCopy(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}

// singleJoiningSlash joins two URL path segments with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
