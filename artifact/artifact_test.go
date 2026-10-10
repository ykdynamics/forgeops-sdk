package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// testRegistry is a minimal OCI distribution registry for one process: blobs
// and manifests by digest, tags, monolithic uploads, optional bearer auth, and
// hooks that make it lie, so every refusal can be shown.
type testRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // by digest and by tag
	lie       map[string][]byte // serve these bytes for this digest instead
	bearer    bool              // require a token from /token
	tokenKey  string            // "token" or "access_token"
	scopes    []string          // scopes the token endpoint was asked for
}

func newRegistry(t *testing.T) (*testRegistry, Repository) {
	t.Helper()
	r := &testRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}, lie: map[string][]byte{}, tokenKey: "token"}
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return r, Repository{Scheme: "http", Host: u.Host, Path: "vendor/inventory"}
}

func (r *testRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.URL.Path == "/token" {
		r.scopes = append(r.scopes, req.URL.Query().Get("scope"))
		_ = json.NewEncoder(w).Encode(map[string]string{r.tokenKey: "tok"})
		return
	}
	if r.bearer && req.Header.Get("Authorization") != "Bearer tok" {
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="http://%s/token",service="test"`, req.Host))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/v2/vendor/inventory")
	switch {
	case req.Method == http.MethodPost && rest == "/blobs/uploads/":
		w.Header().Set("Location", "/v2/vendor/inventory/blobs/uploads/one")
		w.WriteHeader(http.StatusAccepted)
	case req.Method == http.MethodPut && strings.HasPrefix(rest, "/blobs/uploads/"):
		b, _ := io.ReadAll(req.Body)
		d := req.URL.Query().Get("digest")
		if Digest(b) != d {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.blobs[d] = b
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(rest, "/blobs/"):
		d := strings.TrimPrefix(rest, "/blobs/")
		b, ok := r.blobs[d]
		if l, lying := r.lie[d]; lying {
			b, ok = l, true
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	case req.Method == http.MethodPut && strings.HasPrefix(rest, "/manifests/"):
		b, _ := io.ReadAll(req.Body)
		ref := strings.TrimPrefix(rest, "/manifests/")
		r.manifests[ref] = b
		r.manifests[Digest(b)] = b
		w.Header().Set("Docker-Content-Digest", Digest(b))
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(rest, "/manifests/"):
		ref := strings.TrimPrefix(rest, "/manifests/")
		b, ok := r.manifests[ref]
		if l, lying := r.lie[ref]; lying {
			b, ok = l, true
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

var (
	impl  = []byte("#!/bin/sh\necho inventory\n")
	pins  = map[string]string{"inventory.check": Digest(impl)}
	arm64 = Expect{OS: "linux", Arch: "arm64", Pins: pins}
)

func mustBuild(t *testing.T, files []File, goos, goarch string) *Image {
	t.Helper()
	img, err := Build(files, goos, goarch)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func push(t *testing.T, repo Repository, img *Image, tag string) {
	t.Helper()
	if _, err := (&Client{Repo: repo}).Push(context.Background(), img, tag); err != nil {
		t.Fatalf("push: %v", err)
	}
}

// staging is a path that does not exist yet, beside an "installed" directory
// whose content must survive any refused pull.
func staging(t *testing.T) (string, string) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed")
	_ = os.Mkdir(installed, 0o755)
	_ = os.WriteFile(filepath.Join(installed, "inventory.check"), []byte("previous"), 0o755)
	return filepath.Join(dir, "staging"), installed
}

func refused(t *testing.T, repo Repository, digest string, exp Expect, want string) {
	t.Helper()
	stage, installed := staging(t)
	_, err := (&Client{Repo: repo}).Pull(context.Background(), digest, exp, stage)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal mentioning %q, got: %v", want, err)
	}
	if _, statErr := os.Stat(stage); !os.IsNotExist(statErr) {
		t.Fatal("a refused pull left its staging directory behind")
	}
	if b, _ := os.ReadFile(filepath.Join(installed, "inventory.check")); string(b) != "previous" {
		t.Fatal("a refused pull touched the installed implementation")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a := mustBuild(t, []File{{"b", []byte("2")}, {"a", []byte("1")}}, "linux", "arm64")
	b := mustBuild(t, []File{{"a", []byte("1")}, {"b", []byte("2")}}, "linux", "arm64")
	if a.ManifestDigest != b.ManifestDigest || a.LayerDigest != b.LayerDigest {
		t.Fatalf("the same files gave two images: %s vs %s", a.ManifestDigest, b.ManifestDigest)
	}
	if c := mustBuild(t, []File{{"a", []byte("1")}, {"b", []byte("2")}}, "linux", "amd64"); c.ManifestDigest == a.ManifestDigest {
		t.Fatal("two platforms gave one manifest digest")
	}
}

func TestBuildRefusesWhatCannotBeCarried(t *testing.T) {
	for _, files := range [][]File{
		nil,
		{{"../x", impl}},
		{{"dir/x", impl}},
		{{"x", impl}, {"x", impl}},
	} {
		if _, err := Build(files, "linux", "arm64"); err == nil {
			t.Errorf("Build accepted %v", files)
		}
	}
	if _, err := Build([]File{{"x", impl}}, "", "arm64"); err == nil {
		t.Error("Build accepted an image without a platform")
	}
}

func TestPushThenPullByDigest(t *testing.T) {
	_, repo := newRegistry(t)
	img := mustBuild(t, []File{{"inventory.check", impl}}, "linux", "arm64")
	push(t, repo, img, "v1")
	stage, _ := staging(t)
	paths, err := (&Client{Repo: repo}).Pull(context.Background(), img.ManifestDigest, arm64, stage)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if b, _ := os.ReadFile(paths["inventory.check"]); !bytes.Equal(b, impl) {
		t.Fatal("the staged file is not the pushed bytes")
	}
}

// A tag can be moved to other bytes; a pull by digest never asks what a tag
// means, so it still gets exactly the bytes it was authorized for.
func TestAMovedTagCannotChangeWhatIsPulled(t *testing.T) {
	_, repo := newRegistry(t)
	authorized := mustBuild(t, []File{{"inventory.check", impl}}, "linux", "arm64")
	push(t, repo, authorized, "v1")
	other := mustBuild(t, []File{{"inventory.check", []byte("other bytes")}}, "linux", "arm64")
	push(t, repo, other, "v1") // the tag now names other bytes
	stage, _ := staging(t)
	paths, err := (&Client{Repo: repo}).Pull(context.Background(), authorized.ManifestDigest, arm64, stage)
	if err != nil {
		t.Fatalf("pull by digest after the tag moved: %v", err)
	}
	if b, _ := os.ReadFile(paths["inventory.check"]); !bytes.Equal(b, impl) {
		t.Fatal("the moved tag changed the pulled bytes")
	}
	refused(t, repo, "v1", arm64, "pulled by digest, never by tag")
}

func TestPullRefusesWhatItCannotVerify(t *testing.T) {
	reg, repo := newRegistry(t)
	img := mustBuild(t, []File{{"inventory.check", impl}}, "linux", "arm64")
	push(t, repo, img, "")

	t.Run("wrong digest", func(t *testing.T) {
		refused(t, repo, Digest([]byte("nothing")), arm64, "HTTP 404")
	})
	t.Run("wrong platform", func(t *testing.T) {
		refused(t, repo, img.ManifestDigest, Expect{OS: "linux", Arch: "amd64", Pins: pins}, "expects linux/amd64")
	})
	t.Run("pin mismatch", func(t *testing.T) {
		refused(t, repo, img.ManifestDigest, Expect{OS: "linux", Arch: "arm64", Pins: map[string]string{"inventory.check": Digest([]byte("reviewed bytes"))}}, "the pin authorizes")
	})
	t.Run("pinned file missing", func(t *testing.T) {
		refused(t, repo, img.ManifestDigest, Expect{OS: "linux", Arch: "arm64", Pins: map[string]string{"inventory.check": pins["inventory.check"], "other": pins["inventory.check"]}}, "is not in the artifact")
	})
	t.Run("unpinned file", func(t *testing.T) {
		two := mustBuild(t, []File{{"inventory.check", impl}, {"extra", impl}}, "linux", "arm64")
		push(t, repo, two, "")
		refused(t, repo, two.ManifestDigest, arm64, "not authorized by any pin")
	})
	t.Run("registry returns other manifest bytes", func(t *testing.T) {
		other := mustBuild(t, []File{{"inventory.check", []byte("substituted")}}, "linux", "arm64")
		push(t, repo, other, "")
		reg.lie[img.ManifestDigest] = other.Manifest
		defer delete(reg.lie, img.ManifestDigest)
		refused(t, repo, img.ManifestDigest, arm64, "returned bytes hashing to")
	})
	t.Run("registry returns other layer bytes", func(t *testing.T) {
		reg.lie[img.LayerDigest] = []byte("tampered")
		defer delete(reg.lie, img.LayerDigest)
		refused(t, repo, img.ManifestDigest, arm64, "returned bytes hashing to")
	})
}

// hostile builds a well-formed image around a hand-made layer, so the only
// thing wrong with it is the archive.
func hostile(t *testing.T, repo Repository, layer []byte) string {
	t.Helper()
	img := mustBuild(t, []File{{"placeholder", impl}}, "linux", "arm64")
	img.Layer, img.LayerDigest = layer, Digest(layer)
	var m map[string]any
	_ = json.Unmarshal(img.Manifest, &m)
	m["layers"] = []any{map[string]any{"mediaType": MediaTypeLayer, "digest": img.LayerDigest, "size": len(layer)}}
	img.Manifest, _ = json.Marshal(m)
	img.ManifestDigest = Digest(img.Manifest)
	push(t, repo, img, "")
	return img.ManifestDigest
}

func tarGz(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, h := range entries {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(impl))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(impl)
		}
	}
	_ = tw.Close()
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return gz.Bytes()
}

func TestPullRefusesHostileArchives(t *testing.T) {
	_, repo := newRegistry(t)
	cases := map[string]struct {
		layer []byte
		want  string
	}{
		"path traversal": {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "../inventory.check", Mode: 0o755}), "not a flat file name"},
		"absolute path":  {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "/etc/inventory.check", Mode: 0o755}), "not a flat file name"},
		"nested path":    {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "bin/inventory.check", Mode: 0o755}), "not a flat file name"},
		"symlink":        {tarGz(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "inventory.check", Linkname: "/bin/sh"}), "not a regular file"},
		"directory":      {tarGz(t, &tar.Header{Typeflag: tar.TypeDir, Name: "inventory.check", Mode: 0o755}), "not a regular file"},
		"duplicate":      {tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "inventory.check", Mode: 0o755}, &tar.Header{Typeflag: tar.TypeReg, Name: "inventory.check", Mode: 0o755}), "appears twice"},
		"not gzip":       {[]byte("plain bytes, not an archive"), "not gzip"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			refused(t, repo, hostile(t, repo, c.layer), arm64, c.want)
		})
	}
}

// A token registry (GHCR-like) is answered with a token scoped to exactly this
// repository and the access needed; both answer shapes are read.
func TestBearerTokenIsScopedToTheRepository(t *testing.T) {
	for _, key := range []string{"token", "access_token"} {
		t.Run(key, func(t *testing.T) {
			reg, repo := newRegistry(t)
			reg.bearer, reg.tokenKey = true, key
			img := mustBuild(t, []File{{"inventory.check", impl}}, "linux", "arm64")
			c := &Client{Repo: repo, Creds: Credentials{User: "vendor", Password: "secret"}}
			if _, err := c.Push(context.Background(), img, ""); err != nil {
				t.Fatalf("push with a token: %v", err)
			}
			stage, _ := staging(t)
			if _, err := (&Client{Repo: repo, Creds: Credentials{User: "edge", Password: "pull-only"}}).Pull(context.Background(), img.ManifestDigest, arm64, stage); err != nil {
				t.Fatalf("pull with a token: %v", err)
			}
			want := map[string]bool{"repository:vendor/inventory:pull,push": true, "repository:vendor/inventory:pull": true}
			for _, s := range reg.scopes {
				if !want[s] {
					t.Fatalf("a token was asked for scope %q", s)
				}
			}
		})
	}
}

func TestLayoutRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	img := mustBuild(t, []File{{"inventory.check", impl}}, "linux", "arm64")
	if err := WriteLayout(dir, img); err != nil {
		t.Fatal(err)
	}
	back, err := ReadLayout(dir)
	if err != nil || back.ManifestDigest != img.ManifestDigest || !bytes.Equal(back.Layer, img.Layer) {
		t.Fatalf("layout round trip: %v", err)
	}
	if err := os.WriteFile(blobPath(dir, img.LayerDigest), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLayout(dir); err == nil || !strings.Contains(err.Error(), "hashing to") {
		t.Fatalf("a tampered layout was read: %v", err)
	}
}
