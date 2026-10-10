package sdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeRuntime records the runtime callbacks a capability makes.
type fakeRuntime struct {
	mu       sync.Mutex
	progress []map[string]any
	logs     []map[string]any
	bearer   string
	secrets  map[string]string
}

func (f *fakeRuntime) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /runtime/runs/{id}/progress", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r, &f.progress)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /runtime/runs/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		f.capture(r, &f.logs)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /runtime/runs/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.bearer = r.Header.Get("Authorization")
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.secrets)
	})
	return httptest.NewServer(mux)
}

func (f *fakeRuntime) capture(r *http.Request, into *[]map[string]any) {
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	f.mu.Lock()
	f.bearer = r.Header.Get("Authorization")
	*into = append(*into, m)
	f.mu.Unlock()
}

func TestServe_ParsesInputAndReturnsOutput(t *testing.T) {
	h := NewHandler(func(_ context.Context, rc *Context) (any, error) {
		var in struct {
			Name string `json:"name"`
		}
		if err := rc.Bind(&in); err != nil {
			return nil, err
		}
		return map[string]string{"hello": in.Name, "run": rc.RunID}, nil
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"run_id":"run-1","input":{"name":"world"}}`
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]string
	_ = json.Unmarshal(raw, &out)
	if out["hello"] != "world" || out["run"] != "run-1" {
		t.Errorf("unexpected output: %s", raw)
	}
}

func TestContext_CallbacksHitRuntimeWithBearer(t *testing.T) {
	fr := &fakeRuntime{secrets: map[string]string{"api_token": "sk-xyz"}}
	rt := fr.server()
	defer rt.Close()

	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		if err := rc.Progress(ctx, 50, "halfway"); err != nil {
			return nil, err
		}
		if err := rc.Log(ctx, "line one", "line two"); err != nil {
			return nil, err
		}
		secrets, err := rc.Secrets(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]any{"secret_seen": secrets["api_token"]}, nil
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"run_id":"run-9","input":{},"runtime_token":"tok-abc","runtime_url":"` + rt.URL + `"}`
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	out, _ := io.ReadAll(resp.Body)

	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.progress) != 1 || fr.progress[0]["message"] != "halfway" {
		t.Errorf("progress not recorded: %+v", fr.progress)
	}
	if len(fr.logs) != 1 {
		t.Errorf("logs not recorded: %+v", fr.logs)
	}
	if fr.bearer != "Bearer tok-abc" {
		t.Errorf("runtime token not sent as bearer: %q", fr.bearer)
	}
	if !strings.Contains(string(out), "sk-xyz") {
		t.Errorf("secret not delivered to handler: %s", out)
	}
}

func TestNormalizeRuntimeURL(t *testing.T) {
	cases := map[string]string{
		"http://forgeops-runtime:8081":               "http://forgeops-runtime:8081",
		"http://forgeops-runtime:8081/":              "http://forgeops-runtime:8081",
		"https://host/runtime":                       "https://host",
		"https://host/runtime/":                      "https://host",
		"https://forgeops.pg.ykdynamics.com/runtime": "https://forgeops.pg.ykdynamics.com",
		"": "",
	}
	for in, want := range cases {
		if got := normalizeRuntimeURL(in); got != want {
			t.Errorf("normalizeRuntimeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContext_ChildRunByCapabilityKey(t *testing.T) {
	var gotBody map[string]any
	var gotBearer string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /runtime/runs/{id}/child-runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		gotBearer = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	})
	rt := httptest.NewServer(mux)
	defer rt.Close()

	h := NewHandler(func(ctx context.Context, rc *Context) (any, error) {
		return nil, rc.ChildRun(ctx, "scenario.child", map[string]any{"index": 0})
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"run_id":"run-7","input":{},"runtime_token":"tok-z","runtime_url":"` + rt.URL + `"}`
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotBody["capability_key"] != "scenario.child" {
		t.Errorf("child-run did not send capability_key: %+v", gotBody)
	}
	if gotBearer != "Bearer tok-z" {
		t.Errorf("child-run missing bearer: %q", gotBearer)
	}
}

func TestServe_HandlerErrorFailsRun(t *testing.T) {
	h := NewHandler(func(_ context.Context, _ *Context) (any, error) {
		return nil, errString("boom")
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/run", "application/json", strings.NewReader(`{"run_id":"r"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (so the executor fails the run)", resp.StatusCode)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
