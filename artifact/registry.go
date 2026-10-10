package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Repository is one repository on one registry: host[:port]/path.
type Repository struct {
	Scheme string // "https" unless a test or a local registry says otherwise
	Host   string
	Path   string
}

// ParseRepository reads "host[:port]/path" (no scheme, no tag, no digest).
func ParseRepository(s string) (Repository, error) {
	host, path, ok := strings.Cut(s, "/")
	if !ok || host == "" || path == "" || strings.ContainsAny(s, "@ ") || strings.Contains(path, ":") {
		return Repository{}, fmt.Errorf("artifact: %q is not host[:port]/path", s)
	}
	return Repository{Scheme: "https", Host: host, Path: path}, nil
}

func (r Repository) String() string { return r.Host + "/" + r.Path }

func (r Repository) base() string { return r.Scheme + "://" + r.Host + "/v2/" + r.Path }

// Credentials for one registry. Empty means anonymous.
type Credentials struct{ User, Password string }

// Client talks to an OCI distribution registry for one repository. A token
// it obtains is scoped to that repository and to the access it asked for.
type Client struct {
	HTTP  *http.Client
	Repo  Repository
	Creds Credentials
	token string
}

// MaxBlob bounds any blob this client will read (default 256 MiB).
const MaxBlob = 256 << 20

// Push uploads img and, when tag is not empty, tags it. It returns the
// manifest digest the registry reports, which must be the one Build made.
func (c *Client) Push(ctx context.Context, img *Image, tag string) (string, error) {
	for _, blob := range [][]byte{img.Config, img.Layer} {
		if err := c.putBlob(ctx, blob); err != nil {
			return "", err
		}
	}
	refs := []string{img.ManifestDigest}
	if tag != "" {
		refs = append(refs, tag)
	}
	var reported string
	for _, ref := range refs {
		resp, err := c.do(ctx, http.MethodPut, c.Repo.base()+"/manifests/"+ref, img.Manifest, MediaTypeManifest, "pull,push")
		if err != nil {
			return "", err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("artifact: push manifest as %s: HTTP %d", ref, resp.StatusCode)
		}
		if d := resp.Header.Get("Docker-Content-Digest"); d != "" {
			reported = d
		}
	}
	if reported != "" && reported != img.ManifestDigest {
		return "", fmt.Errorf("artifact: the registry reports %s for the manifest pushed as %s", reported, img.ManifestDigest)
	}
	return img.ManifestDigest, nil
}

func (c *Client) putBlob(ctx context.Context, blob []byte) error {
	digest := Digest(blob)
	if resp, err := c.do(ctx, http.MethodHead, c.Repo.base()+"/blobs/"+digest, nil, "", "pull,push"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil // already there, content-addressed
		}
	}
	resp, err := c.do(ctx, http.MethodPost, c.Repo.base()+"/blobs/uploads/", nil, "", "pull,push")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("artifact: start upload: HTTP %d", resp.StatusCode)
	}
	loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
	if err != nil {
		return fmt.Errorf("artifact: upload location: %w", err)
	}
	q := loc.Query()
	q.Set("digest", digest)
	loc.RawQuery = q.Encode()
	resp, err = c.do(ctx, http.MethodPut, loc.String(), blob, "application/octet-stream", "pull,push")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("artifact: upload blob %s: HTTP %d", digest, resp.StatusCode)
	}
	return nil
}

// Expect is what a pull must find, or it is refused.
type Expect struct {
	OS, Arch string
	// Pins maps each file the artifact must carry to its implementation digest.
	// A file without a pin, or a pin without its file, is refused.
	Pins map[string]string
}

// Pull fetches the image named by digest, verifies it against expect, and
// extracts its files into staging (which must not exist yet). It returns the
// staged paths only when every check passed; on any failure staging is removed,
// so nothing partially verified is left to install.
func (c *Client) Pull(ctx context.Context, digest string, expect Expect, staging string) (paths map[string]string, err error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("artifact: %q is not a sha256 digest; artifacts are pulled by digest, never by tag", digest)
	}
	if len(expect.Pins) == 0 || expect.OS == "" || expect.Arch == "" {
		return nil, fmt.Errorf("artifact: a pull needs the platform and a pin for every file it may install")
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		return nil, fmt.Errorf("artifact: staging: %w", err)
	}
	defer func() {
		if err != nil {
			os.RemoveAll(staging)
		}
	}()

	// The manifest is believed only once its bytes hash to the digest asked for.
	raw, err := c.get(ctx, "/manifests/"+digest, MediaTypeManifest)
	if err != nil {
		return nil, err
	}
	if got := Digest(raw); got != digest {
		return nil, fmt.Errorf("artifact: asked for manifest %s, the registry returned bytes hashing to %s", digest, got)
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}

	config, err := c.blob(ctx, m.Config.Digest)
	if err != nil {
		return nil, err
	}
	var platform struct {
		OS   string `json:"os"`
		Arch string `json:"architecture"`
	}
	if err := json.Unmarshal(config, &platform); err != nil {
		return nil, fmt.Errorf("artifact: config is not JSON: %w", err)
	}
	if platform.OS != expect.OS || platform.Arch != expect.Arch {
		return nil, fmt.Errorf("artifact: the image is %s/%s, this install expects %s/%s", platform.OS, platform.Arch, expect.OS, expect.Arch)
	}

	layer, err := c.blob(ctx, m.Layers[0].Digest)
	if err != nil {
		return nil, err
	}
	paths, err = extract(layer, staging, expect.Pins)
	if err != nil {
		return nil, err
	}
	return paths, nil
}

// extract unpacks only flat regular files, each at most MaxBlob, into staging,
// and checks each against its pin. Anything else — a directory, a link, a
// device, a path with a separator, a duplicate, an unpinned file, a missing
// pinned file — refuses the whole artifact.
func extract(layer []byte, staging string, pins map[string]string) (map[string]string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, fmt.Errorf("artifact: layer is not gzip: %w", err)
	}
	tr := tar.NewReader(zr)
	paths := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("artifact: layer is not a readable tar: %w", err)
		}
		switch {
		case hdr.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("artifact: %q is not a regular file (type %q); refusing the artifact", hdr.Name, string(hdr.Typeflag))
		case !ValidName(hdr.Name):
			return nil, fmt.Errorf("artifact: %q is not a flat file name; refusing the artifact", hdr.Name)
		case paths[hdr.Name] != "":
			return nil, fmt.Errorf("artifact: %q appears twice; refusing the artifact", hdr.Name)
		case pins[hdr.Name] == "":
			return nil, fmt.Errorf("artifact: %q is carried but not authorized by any pin; refusing the artifact", hdr.Name)
		case hdr.Size > MaxBlob:
			return nil, fmt.Errorf("artifact: %q is %d bytes, over the %d limit", hdr.Name, hdr.Size, MaxBlob)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxBlob+1))
		if err != nil || int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("artifact: %q is truncated or unreadable", hdr.Name)
		}
		if got := Digest(data); got != pins[hdr.Name] {
			return nil, fmt.Errorf("artifact: %s: the artifact carries %s, the pin authorizes %s", hdr.Name, got, pins[hdr.Name])
		}
		p := filepath.Join(staging, hdr.Name)
		if err := os.WriteFile(p, data, 0o755); err != nil {
			return nil, err
		}
		paths[hdr.Name] = p
	}
	for name := range pins {
		if paths[name] == "" {
			return nil, fmt.Errorf("artifact: the pinned %s is not in the artifact", name)
		}
	}
	return paths, nil
}

// blob fetches a blob and checks it against its digest.
func (c *Client) blob(ctx context.Context, digest string) ([]byte, error) {
	b, err := c.get(ctx, "/blobs/"+digest, "")
	if err != nil {
		return nil, err
	}
	if got := Digest(b); got != digest {
		return nil, fmt.Errorf("artifact: asked for blob %s, the registry returned bytes hashing to %s", digest, got)
	}
	return b, nil
}

func (c *Client) get(ctx context.Context, path, accept string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, c.Repo.base()+path, nil, accept, "pull")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact: GET %s: HTTP %d", path, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBlob+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBlob {
		return nil, fmt.Errorf("artifact: %s is over the %d byte limit", path, MaxBlob)
	}
	return b, nil
}

// do sends one request, answering one auth challenge: Basic with the
// credentials, or a Bearer token exchanged for exactly this repository and
// the access asked for (pull, or pull,push).
func (c *Client) do(ctx context.Context, method, u string, body []byte, contentType, access string) (*http.Response, error) {
	send := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			if method == http.MethodGet || method == http.MethodHead {
				req.Header.Set("Accept", contentType)
			} else {
				req.Header.Set("Content-Type", contentType)
			}
		}
		switch {
		case c.token != "":
			req.Header.Set("Authorization", "Bearer "+c.token)
		case c.Creds.User != "":
			req.SetBasicAuth(c.Creds.User, c.Creds.Password)
		}
		return c.http().Do(req)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("Www-Authenticate")
	resp.Body.Close()
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") || c.token != "" {
		return nil, fmt.Errorf("artifact: %s %s: unauthorized (check the credentials for %s)", method, u, c.Repo.Host)
	}
	if err := c.exchange(ctx, challenge, access); err != nil {
		return nil, err
	}
	return send()
}

// exchange trades the credentials for a bearer token scoped to this one
// repository. Registries answer {"token": …} or {"access_token": …}; both are
// read, and an answer with neither is refused rather than sent on empty.
func (c *Client) exchange(ctx context.Context, challenge, access string) error {
	params := map[string]string{}
	for _, part := range strings.Split(challenge[len("bearer "):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			params[strings.ToLower(k)] = strings.Trim(v, `"`)
		}
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Scheme == "" {
		return fmt.Errorf("artifact: the registry's token challenge names no usable realm")
	}
	q := realm.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	q.Set("scope", "repository:"+c.Repo.Path+":"+access)
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if c.Creds.User != "" {
		req.SetBasicAuth(c.Creds.User, c.Creds.Password)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("artifact: token exchange for %s: HTTP %d", c.Repo, resp.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return fmt.Errorf("artifact: token answer is not JSON: %w", err)
	}
	c.token = tok.Token
	if c.token == "" {
		c.token = tok.AccessToken
	}
	if c.token == "" {
		return fmt.Errorf("artifact: the token answer carries no token")
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
