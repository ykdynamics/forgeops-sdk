// Package artifact delivers a capability's exact bytes as a single-platform OCI
// image, by digest, and verifies them on the way in.
//
// Three identities stay distinct, and this package keeps their binding:
//
//	implementation digest   sha256 of the executable (capability.yaml identity.artifactDigest)
//	package identity        the canonical capability.yaml (key, version, its digest)
//	OCI manifest digest     sha256 of the image manifest that carries the executable
//
// Build packs the bytes that were hashed — never a rebuild — into one layer,
// deterministically: the same files give the same manifest digest. Pull asks
// the registry for a DIGEST, never a tag, so a moved tag cannot change what is
// fetched; it checks the manifest's bytes against the digest asked for before
// believing anything in them, checks every blob the same way, refuses a
// platform other than the expected one, extracts into a staging directory
// under strict rules (flat regular files only, bounded sizes), and checks each
// file against its pinned implementation digest. Only a fully verified set is
// ever returned for installation.
//
// One image per platform, deliberately: an index digest names a set, and the
// edge would still have to be told which member to trust.
//
// This API is experimental and versioned with the module (ADR-010).
package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Media types of the image this package builds and accepts.
const (
	MediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeConfig   = "application/vnd.oci.image.config.v1+json"
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// File is one executable carried by an artifact, under a flat name.
type File struct {
	Name string
	Data []byte
}

// Image is a built single-platform image: its three blobs and their digests.
type Image struct {
	Manifest       []byte
	ManifestDigest string
	Config         []byte
	ConfigDigest   string
	Layer          []byte
	LayerDigest    string
}

// Digest is the "sha256:<hex>" digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidName reports whether name can be carried: one flat path element, no
// separators, no dot entries. The same rule refuses a hostile archive on pull.
func ValidName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) &&
		!strings.HasPrefix(name, "-") && len(name) <= 128
}

// Build packs files into one deterministic image for os/arch. Entries are
// sorted, owned by 0:0, mode 0755, dated the Unix epoch, and gzipped without a
// name or a timestamp, so the same files always give the same digests.
func Build(files []File, goos, goarch string) (*Image, error) {
	if goos == "" || goarch == "" {
		return nil, fmt.Errorf("artifact: an image is built for one exact platform (got %q/%q)", goos, goarch)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("artifact: nothing to carry")
	}
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var rawTar bytes.Buffer
	tw := tar.NewWriter(&rawTar)
	for i, f := range sorted {
		if !ValidName(f.Name) {
			return nil, fmt.Errorf("artifact: %q is not a flat file name", f.Name)
		}
		if i > 0 && sorted[i-1].Name == f.Name {
			return nil, fmt.Errorf("artifact: %q is carried twice", f.Name)
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg, Name: f.Name, Mode: 0o755, Size: int64(len(f.Data)),
			Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(rawTar.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	img := &Image{Layer: gz.Bytes()}
	img.LayerDigest = Digest(img.Layer)
	config := map[string]any{
		"architecture": goarch,
		"os":           goos,
		"config":       map[string]any{},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{Digest(rawTar.Bytes())}},
	}
	if img.Config, err = json.Marshal(config); err != nil {
		return nil, err
	}
	img.ConfigDigest = Digest(img.Config)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     MediaTypeManifest,
		"config":        map[string]any{"mediaType": MediaTypeConfig, "digest": img.ConfigDigest, "size": len(img.Config)},
		"layers":        []any{map[string]any{"mediaType": MediaTypeLayer, "digest": img.LayerDigest, "size": len(img.Layer)}},
	}
	if img.Manifest, err = json.Marshal(manifest); err != nil {
		return nil, err
	}
	img.ManifestDigest = Digest(img.Manifest)
	return img, nil
}

// WriteLayout writes img as an OCI image layout in dir (oci-layout, index.json
// and blobs/sha256/*), the on-disk form `forgeops-cap push` reads.
func WriteLayout(dir string, img *Image) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return err
	}
	for _, b := range [][]byte{img.Manifest, img.Config, img.Layer} {
		if err := os.WriteFile(blobPath(dir, Digest(b)), b, 0o644); err != nil {
			return err
		}
	}
	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"manifests": []any{map[string]any{
			"mediaType": MediaTypeManifest, "digest": img.ManifestDigest, "size": len(img.Manifest),
		}},
	})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), index, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644)
}

// ReadLayout reads a layout written by WriteLayout, checking every blob
// against its digest: a layout is trusted no more than a registry.
func ReadLayout(dir string) (*Image, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &index); err != nil || len(index.Manifests) != 1 {
		return nil, fmt.Errorf("artifact: %s/index.json must name exactly one manifest", dir)
	}
	img := &Image{ManifestDigest: index.Manifests[0].Digest}
	if img.Manifest, err = readBlob(dir, img.ManifestDigest); err != nil {
		return nil, err
	}
	m, err := parseManifest(img.Manifest)
	if err != nil {
		return nil, err
	}
	img.ConfigDigest, img.LayerDigest = m.Config.Digest, m.Layers[0].Digest
	if img.Config, err = readBlob(dir, img.ConfigDigest); err != nil {
		return nil, err
	}
	if img.Layer, err = readBlob(dir, img.LayerDigest); err != nil {
		return nil, err
	}
	return img, nil
}

func blobPath(dir, digest string) string {
	return filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

func readBlob(dir, digest string) ([]byte, error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("artifact: %q is not a sha256 digest", digest)
	}
	b, err := os.ReadFile(blobPath(dir, digest))
	if err != nil {
		return nil, err
	}
	if got := Digest(b); got != digest {
		return nil, fmt.Errorf("artifact: blob %s holds bytes hashing to %s", digest, got)
	}
	return b, nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

// parseManifest accepts exactly the shape Build makes: an image manifest (not
// an index) with one gzip layer.
func parseManifest(b []byte) (*manifest, error) {
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("artifact: manifest is not JSON: %w", err)
	}
	if m.SchemaVersion != 2 || (m.MediaType != "" && m.MediaType != MediaTypeManifest) {
		return nil, fmt.Errorf("artifact: not a single-platform OCI image manifest (mediaType %q)", m.MediaType)
	}
	if len(m.Layers) != 1 || m.Layers[0].MediaType != MediaTypeLayer {
		return nil, fmt.Errorf("artifact: an artifact carries exactly one %s layer", MediaTypeLayer)
	}
	if !validDigest(m.Config.Digest) || !validDigest(m.Layers[0].Digest) {
		return nil, fmt.Errorf("artifact: manifest names a malformed digest")
	}
	return &m, nil
}

func validDigest(d string) bool {
	h := strings.TrimPrefix(d, "sha256:")
	if len(d) != len(h)+7 || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}
