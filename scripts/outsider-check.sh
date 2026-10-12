#!/usr/bin/env bash
# outsider-check.sh — an outside developer's first steps, from nothing: a fresh
# module cache, no go env file, no GOFLAGS, no workspace, the SDK release from
# the public module proxy. Scaffold, validate, build with Go's defaults
# (-mod=readonly), conformance. Needs the network.
#
#   make outsider-check SDK_VERSION=vX.Y.Z[-pre]            CLI built from this tree
#   make outsider-check SDK_VERSION=vX.Y.Z[-pre] CLI=release CLI from `go install …@SDK_VERSION`
#
# CLI=tree checks this tree's forgeops-cap against a published SDK (before a
# release); CLI=release is the journey exactly as published (after it).
set -euo pipefail

: "${SDK_VERSION:?set SDK_VERSION=vX.Y.Z[-pre], a published forgeops-sdk release}"
CLI="${CLI:-tree}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

work="$(mktemp -d)"
# The module cache is read-only by design; make it removable.
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
export GOENV=off GOFLAGS='' GOWORK=off GOPATH="$work/gopath" GOMODCACHE="$work/gopath/pkg/mod" GOCACHE="$work/cache"
unset GOPRIVATE GONOPROXY GONOSUMDB GOPROXY GOSUMDB
cap="$work/bin/forgeops-cap"

step() { printf '\n== %s ==\n' "$*"; }

case "$CLI" in
  tree)
    step "forgeops-cap from this tree ($(git -C "$root" rev-parse --short HEAD))"
    (cd "$root" && go build -o "$cap" ./cmd/forgeops-cap) ;;
  release)
    step "go install github.com/ykdynamics/forgeops-sdk/cmd/forgeops-cap@$SDK_VERSION"
    GOBIN="$work/bin" go install "github.com/ykdynamics/forgeops-sdk/cmd/forgeops-cap@$SDK_VERSION" ;;
  *) echo "CLI must be tree or release (got $CLI)" >&2; exit 2 ;;
esac

cd "$work"
step "init (SDK $SDK_VERSION)"
"$cap" init demo.service.status --sdk-version "$SDK_VERSION"
cd demo-service-status

step "validate"
"$cap" validate capability.yaml

step "go build, as a developer runs it (-mod=readonly)"
go build -o /dev/null .
echo "OK: builds with Go's defaults"

step "conformance"
"$cap" conformance . --input '{"service":"demo-service"}'

echo
echo "OUTSIDER CHECK PASSED: SDK $SDK_VERSION, forgeops-cap from $CLI"
