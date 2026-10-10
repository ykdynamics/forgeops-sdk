package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// declaredPolicy parses a policy declaring each server's authority with
// AllowPrivate (the test seam — the test stack runs on loopback).
func declaredPolicy(t *testing.T, allowPrivate bool, urls ...string) *Policy {
	t.Helper()
	parts := make([]string, 0, len(urls))
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse %q: %v", u, err)
		}
		parts = append(parts, parsed.Scheme+"://"+parsed.Host)
	}
	p, err := Parse(strings.Join(parts, ","), allowPrivate)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

func TestClient_AllowsDeclaredDestination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	c := Client(declaredPolicy(t, true, srv.URL), 5*time.Second)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("declared + allowed destination should work: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestClient_DeniesUndeclaredHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	c := Client(declaredPolicy(t, true, "https://api.acme.com"), 5*time.Second)
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("undeclared host must be denied, got %v", err)
	}
}

func TestClient_DeniesPrivateWithoutAllowPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	// Declared, but the loopback range is not approved.
	c := Client(declaredPolicy(t, false, srv.URL), 5*time.Second)
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("private destination without AllowPrivate must be denied, got %v", err)
	}
}

func TestClient_NilPolicyDeniesEverything(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	c := Client(nil, 5*time.Second)
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("nil policy must deny all egress")
	}
}

func TestRedirect_ToDeclaredAuthority_StripsHeaders(t *testing.T) {
	var bHit bool
	var sawHeader string
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHit = true
		sawHeader = r.Header.Get("X-Api-Key")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srvB.Close()
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/target", http.StatusFound)
	}))
	defer srvA.Close()

	c := Client(declaredPolicy(t, true, srvA.URL, srvB.URL), 5*time.Second)
	req, _ := http.NewRequest(http.MethodGet, srvA.URL, nil)
	req.Header.Set("X-Api-Key", "secret-value")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("redirect to a declared authority should be followed: %v", err)
	}
	resp.Body.Close()
	if !bHit {
		t.Fatal("redirect was not followed")
	}
	if sawHeader != "" {
		t.Errorf("X-Api-Key %q was forwarded across an authority change", sawHeader)
	}
}

func TestRedirect_ToUndeclaredAuthority_Denied(t *testing.T) {
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srvB.Close()
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/target", http.StatusFound)
	}))
	defer srvA.Close()

	// Only A is declared — the redirect to B must fail closed.
	c := Client(declaredPolicy(t, true, srvA.URL), 5*time.Second)
	_, err := c.Get(srvA.URL)
	if err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("redirect to an undeclared authority must be denied, got %v", err)
	}
}

func TestRedirect_SameAuthority_KeepsHeaders(t *testing.T) {
	var sawHeader string
	var srvA *httptest.Server
	srvA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			http.Redirect(w, r, srvA.URL+"/second", http.StatusFound)
			return
		}
		sawHeader = r.Header.Get("X-Api-Key")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srvA.Close()

	c := Client(declaredPolicy(t, true, srvA.URL), 5*time.Second)
	req, _ := http.NewRequest(http.MethodGet, srvA.URL+"/first", nil)
	req.Header.Set("X-Api-Key", "secret-value")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("same-authority redirect should be followed: %v", err)
	}
	resp.Body.Close()
	if sawHeader != "secret-value" {
		t.Errorf("same-authority redirect dropped the header (got %q)", sawHeader)
	}
}
