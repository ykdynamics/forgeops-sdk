# forgeops-sdk: checks and releases. See RELEASING.md.

SHELL := /bin/bash

MODULE    := github.com/ykdynamics/forgeops-sdk
# The compiler this SDK is qualified with: go.mod's toolchain directive (a test
# keeps buildrecipe.PinnedToolchain equal to it). Release binaries are built
# with exactly this compiler, downloaded by the go command if need be.
TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)
PLATFORMS := linux/amd64 linux/arm64
DIST      := dist

.PHONY: check fmt-check vet test deps-check outsider-check release-build release-tag clean

## check: everything CI runs on a pull request
check: fmt-check vet test deps-check

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./... -count=1

## deps-check: the public SDK depends on the standard library and gopkg.in/yaml.v3
## only; above all, never on a private ForgeOps module.
deps-check:
	@extra="$$(go list -deps ./... | grep '\.' | grep -v '^$(MODULE)' | grep -v '^vendor/' | grep -v '^crypto/internal/' | grep -v '^gopkg.in/yaml.v3$$' || true)"; \
	if [ -n "$$extra" ]; then echo "unexpected dependencies:"; echo "$$extra"; exit 1; fi; \
	echo "dependencies: standard library + gopkg.in/yaml.v3 only"

## outsider-check SDK_VERSION=vX.Y.Z[-pre] [CLI=tree|release]: an outside
## developer's first steps from nothing (fresh module cache, default go
## settings, the release from the public proxy). Needs the network, so it is
## not part of check. See scripts/outsider-check.sh.
outsider-check:
	SDK_VERSION='$(SDK_VERSION)' CLI='$(CLI)' bash scripts/outsider-check.sh

## release-build VERSION=vX.Y.Z[-pre]: forgeops-cap for each platform, built with
## the pinned toolchain and the version stamped in, as tarballs + SHA256SUMS.
release-build:
	@[[ "$(VERSION)" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$ ]] || { echo "VERSION=vX.Y.Z[-pre] required (got '$(VERSION)')"; exit 2; }
	@[ -n "$(TOOLCHAIN)" ] || { echo "go.mod declares no toolchain"; exit 2; }
	rm -rf $(DIST) && mkdir -p $(DIST)
	@set -e; for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; name=forgeops-cap_$(VERSION)_$${os}_$${arch}; \
	  mkdir -p $(DIST)/$$name; \
	  GOTOOLCHAIN=$(TOOLCHAIN) CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOFLAGS= \
	    go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" \
	    -o $(DIST)/$$name/forgeops-cap ./cmd/forgeops-cap; \
	  cp LICENSE README.md $(DIST)/$$name/; \
	  tar -C $(DIST) -czf $(DIST)/$$name.tar.gz --owner=0 --group=0 $$name 2>/dev/null || tar -C $(DIST) -czf $(DIST)/$$name.tar.gz $$name; \
	  rm -rf $(DIST)/$$name; \
	  echo "built $(DIST)/$$name.tar.gz ($(TOOLCHAIN))"; \
	done
	cd $(DIST) && (command -v sha256sum >/dev/null && sha256sum *.tar.gz || shasum -a 256 *.tar.gz) > SHA256SUMS && cat SHA256SUMS

## release-tag VERSION=vX.Y.Z[-pre]: an annotated tag on an up-to-date, clean
## main, created LOCALLY. Pushing it (git push origin VERSION) starts the release
## workflow, which drafts the GitHub release; that push is the owner's step.
release-tag:
	@[[ "$(VERSION)" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$ ]] || { echo "VERSION=vX.Y.Z[-pre] required"; exit 2; }
	@[ "$$(git branch --show-current)" = main ] || { echo "release from main"; exit 2; }
	@[ -z "$$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 2; }
	@git fetch -q origin main && [ "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/main)" ] || { echo "main is not origin/main"; exit 2; }
	@! git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null || { echo "tag $(VERSION) exists"; exit 2; }
	$(MAKE) check
	git tag -a $(VERSION) -m "forgeops-sdk $(VERSION)"
	@echo "tagged $(VERSION) locally. To release: git push origin $(VERSION)"

clean:
	rm -rf $(DIST)
