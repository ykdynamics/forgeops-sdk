package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestCmdPublishPostsToRegistry validates the R5.2c publish handoff: the
// register payload is POSTed to the registry endpoint with the bearer token.
func TestCmdPublishPostsToRegistry(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"capability_key":"acme.pkg.demo","version":"0.1.0"}`))
	}))
	defer srv.Close()

	payload := filepath.Join(t.TempDir(), "register.json")
	raw, _ := json.Marshal(map[string]any{
		"capability_key": "acme.pkg.demo", "version": "0.1.0", "publisher": "acme",
		"manifest": map[string]any{"schemaVersion": "capability.v1"},
	})
	if err := os.WriteFile(payload, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cmdPublish([]string{payload, "--registry", srv.URL, "--token", "op-jwt"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if gotPath != "/v1/registry/capabilities" {
		t.Fatalf("publish path = %q", gotPath)
	}
	if gotAuth != "Bearer op-jwt" {
		t.Fatalf("publish auth = %q", gotAuth)
	}
}

// TestCmdPublishKeyRegistersThePublisherKey validates the one-time key upload.
func TestCmdPublishKeyRegistersThePublisherKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/registry/publishers/acme/key" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"publisher":"acme","fingerprint":"deadbeef"}`))
	}))
	defer srv.Close()

	pub := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(pub, []byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPublishKey([]string{pub, "--registry", srv.URL, "--token", "op-jwt", "--publisher", "acme"}); err != nil {
		t.Fatalf("publish-key: %v", err)
	}
}
