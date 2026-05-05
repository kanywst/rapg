package redact

import (
	"strings"
	"testing"
)

func TestRedact_basic(t *testing.T) {
	in := "DB url is postgres://user:supersecret123@localhost/db, and the API key is sk-ant-abc12345xyz."
	got, n := Redact(in, []Secret{
		{Value: "supersecret123", Label: "DB_URL_PASSWORD"},
		{Value: "sk-ant-abc12345xyz", Label: "ANTHROPIC_API_KEY"},
	})
	if n != 2 {
		t.Errorf("matched count = %d, want 2", n)
	}
	if strings.Contains(got, "supersecret123") || strings.Contains(got, "sk-ant-abc12345xyz") {
		t.Errorf("plaintext leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:DB_URL_PASSWORD]") || !strings.Contains(got, "[REDACTED:ANTHROPIC_API_KEY]") {
		t.Errorf("masks missing: %q", got)
	}
}

func TestRedact_skipsShortValues(t *testing.T) {
	in := "the test passed; testing was fine"
	got, n := Redact(in, []Secret{{Value: "test", Label: "TOO_SHORT"}})
	if n != 0 {
		t.Errorf("matched count = %d, want 0", n)
	}
	if got != in {
		t.Errorf("short value should not have been substituted: %q", got)
	}
}

func TestRedact_longerValueProcessedFirst(t *testing.T) {
	// Both values present; the longer one contains the shorter as a
	// suffix. Without longest-first ordering, masking "abcd1234" first
	// would still leave "wxyzabcd1234" reachable, then masking that
	// longer string would partially overlap. Ordering avoids that.
	in := "longer: wxyzabcd1234; shorter: abcd1234"
	got, n := Redact(in, []Secret{
		{Value: "abcd1234", Label: "SHORT"},
		{Value: "wxyzabcd1234", Label: "LONG"},
	})
	if n != 2 {
		t.Errorf("matched count = %d, want 2", n)
	}
	if strings.Contains(got, "abcd1234") {
		t.Errorf("plaintext leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED:LONG]") || !strings.Contains(got, "[REDACTED:SHORT]") {
		t.Errorf("expected both masks: %q", got)
	}
}

func TestRedact_noMatches(t *testing.T) {
	in := "nothing to redact here"
	got, n := Redact(in, []Secret{{Value: "absent_value_long", Label: "X"}})
	if n != 0 {
		t.Errorf("matched count = %d, want 0", n)
	}
	if got != in {
		t.Errorf("no-match should leave input unchanged")
	}
}

func TestRedact_emptySecretsList(t *testing.T) {
	in := "anything goes"
	got, n := Redact(in, nil)
	if n != 0 || got != in {
		t.Errorf("empty secrets should return input unchanged")
	}
}
