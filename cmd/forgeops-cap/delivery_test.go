package main

import (
	"os"
	"path/filepath"
	"testing"
)

// promote replaces the installed directory with the verified staging one, and
// leaves nothing of either behind.
func TestPromoteReplacesTheInstall(t *testing.T) {
	dir := t.TempDir()
	installed, staging := filepath.Join(dir, "installed"), filepath.Join(dir, "staging")
	for p, content := range map[string]string{installed: "old", staging: "new"} {
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "cap"), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := promote(staging, installed); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(installed, "cap")); string(b) != "new" {
		t.Fatalf("installed holds %q, want the promoted content", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("promote left %d entries, want only the install", len(entries))
	}
}

// A first install has nothing to move aside.
func TestPromoteFirstInstall(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.Mkdir(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := promote(staging, filepath.Join(dir, "installed")); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "installed")); err != nil {
		t.Fatal(err)
	}
}
