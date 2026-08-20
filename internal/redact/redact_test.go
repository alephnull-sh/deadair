package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyedValuesAreStableAndDomainSeparated(t *testing.T) {
	a, err := New([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]byte(strings.Repeat("b", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Value("src", "logs-auth") != a.Value("src", "logs-auth") {
		t.Fatal("same key and value must be stable")
	}
	if a.Value("src", "logs-auth") == b.Value("src", "logs-auth") {
		t.Fatal("different keys must not produce the same pseudonym")
	}
	if a.Value("src", "same") == a.Value("rule", "same") {
		t.Fatal("identifier classes must be domain-separated")
	}
	if a.KeyID() == b.KeyID() || a.KeyID() == "" {
		t.Fatalf("key IDs = %q and %q", a.KeyID(), b.KeyID())
	}
}

func TestLoadTrimsOneLineEndingAndRejectsShortKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redaction.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("k", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyID() != direct.KeyID() {
		t.Fatalf("loaded key ID = %q, direct = %q", loaded.KeyID(), direct.KeyID())
	}
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
