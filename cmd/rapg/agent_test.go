package main

import (
	"slices"
	"testing"

	"github.com/kanywst/rapg/internal/config"
	"github.com/kanywst/rapg/internal/keyagent"
)

// The scoping rules read three states out of .rapg.toml, and two of them are
// distinguished only by nil-versus-empty on Keys. JSON collapses both to an
// absent field, so every one of these states has to survive the round trip
// through the wire representation or the agent silently widens or narrows what
// a project can see.
func TestProjectSurvivesTheWireRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   *config.Project
	}{
		{"no project at all", nil},
		{"namespace only, no whitelist", &config.Project{Namespace: "myapp"}},
		{"explicit deny-all", &config.Project{Namespace: "myapp", Keys: []string{}}},
		{"whitelist", &config.Project{Namespace: "myapp", Keys: []string{"A", "B"}}},
		{"inherit global", &config.Project{Namespace: "myapp", InheritGlobal: true}},
		{"empty namespace is still a project", &config.Project{Namespace: ""}},
		{"deny-all with inherit", &config.Project{Namespace: "x", Keys: []string{}, InheritGlobal: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := projectFromRequest(requestFromProject(tc.in))

			if tc.in == nil {
				if got != nil {
					t.Fatalf("nil project came back as %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("project came back nil")
			}

			if got.Namespace != tc.in.Namespace {
				t.Errorf("namespace = %q, want %q", got.Namespace, tc.in.Namespace)
			}
			if got.InheritGlobal != tc.in.InheritGlobal {
				t.Errorf("inherit_global = %v, want %v", got.InheritGlobal, tc.in.InheritGlobal)
			}
			if (got.Keys == nil) != (tc.in.Keys == nil) {
				t.Errorf("keys nil-ness = %v, want %v (this is the deny-all distinction)",
					got.Keys == nil, tc.in.Keys == nil)
			}
			if !slices.Equal(got.Keys, tc.in.Keys) {
				t.Errorf("keys = %v, want %v", got.Keys, tc.in.Keys)
			}
		})
	}
}

// The three states differ in what Allows reports, which is the thing that
// actually gates injection. Checking it directly guards against a round trip
// that preserves the fields but lands on the wrong policy.
func TestRoundTripPreservesAllowsPolicy(t *testing.T) {
	cases := []struct {
		name  string
		in    *config.Project
		key   string
		allow bool
	}{
		{"no whitelist allows anything", &config.Project{Namespace: "a"}, "DATABASE_URL", true},
		{"deny-all allows nothing", &config.Project{Namespace: "a", Keys: []string{}}, "DATABASE_URL", false},
		{"whitelist allows a member", &config.Project{Namespace: "a", Keys: []string{"DATABASE_URL"}}, "DATABASE_URL", true},
		{"whitelist rejects a non-member", &config.Project{Namespace: "a", Keys: []string{"OTHER"}}, "DATABASE_URL", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := projectFromRequest(requestFromProject(tc.in))
			if got.Allows(tc.key) != tc.allow {
				t.Errorf("Allows(%q) = %v, want %v", tc.key, got.Allows(tc.key), tc.allow)
			}
		})
	}
}

// A request with no project must mean "global only", not "a project whose
// namespace is empty". The two resolve differently in core.GetEnvVars.
func TestAbsentProjectIsNotAnEmptyNamespaceProject(t *testing.T) {
	noProject := projectFromRequest(keyagent.Request{})
	if noProject != nil {
		t.Fatalf("a request with no project produced %+v, want nil", noProject)
	}

	emptyNamespace := projectFromRequest(requestFromProject(&config.Project{Namespace: ""}))
	if emptyNamespace == nil {
		t.Fatal("a project with an empty namespace produced nil")
	}
}
