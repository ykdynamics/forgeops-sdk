# Releasing forgeops-sdk

A release is a git tag `vX.Y.Z` (or `vX.Y.Z-pre`, e.g. `v0.1.0-preview.1`) on
`main`. The tag is the Go module version; the GitHub release carries the
`forgeops-cap` binaries.

## What a release contains

- `forgeops-cap_<version>_linux_amd64.tar.gz` and `…_linux_arm64.tar.gz`: the CLI,
  `LICENSE` and `README.md`.
- `SHA256SUMS` for the tarballs.

The binaries are built with the toolchain pinned in `go.mod` (the go command
downloads it if needed), `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false` and the
version stamped in (`-X main.version`). Two builds of one version produce
byte-identical binaries, so anyone can rebuild and compare.

## Steps

1. **Everything for the release is merged** to `main`, and CI is green.
2. **Check locally** (optional; CI runs the same):
   ```bash
   make check
   make release-build VERSION=v0.1.0-preview.1   # look at dist/, then: make clean
   ```
   And an outside developer's first steps with this tree's `forgeops-cap`,
   against the latest published SDK (needs the network):
   ```bash
   make outsider-check SDK_VERSION=<latest published release>
   ```
3. **Tag on an up-to-date, clean `main`:**
   ```bash
   git checkout main && git pull --ff-only origin main
   make release-tag VERSION=v0.1.0-preview.1      # runs make check, creates the tag locally
   ```
4. **Push the tag** (the owner's step: it starts the release):
   ```bash
   git push origin v0.1.0-preview.1
   ```
   The `release` workflow checks the tag is on `main`, runs `make check`, builds
   and creates a **draft** GitHub release, marked pre-release when the version
   has a `-` suffix.
5. **Review the draft** (assets, checksums, notes) and publish it on GitHub.
6. **Walk the published journey** once the module proxy serves the tag:
   ```bash
   make outsider-check SDK_VERSION=v0.1.0-preview.1 CLI=release
   ```

## Rules

- **Never move or delete a published tag.** A Go module version is immutable
  once anyone has fetched it; a fix is a new version. A tag that was pushed by
  mistake and never published may be deleted only before anyone fetched it.
- **A breaking change needs a new version** with migration notes; within a
  version the documented contract stays stable (ADR-010 in forgeops-control).
- **Changing the toolchain** changes every digest a capability pins: update
  `go.mod`'s `toolchain` and `buildrecipe.PinnedToolchain` together (a test
  enforces it), and say so in the release notes.

## While the repository is private

`go install`/`go get` of a private module needs `GOPRIVATE=github.com/ykdynamics/*`
and Git access. The released tarballs work without either.
