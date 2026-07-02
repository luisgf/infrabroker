# ssh-broker build. The version is derived from the git tag and injected into
# the binaries so the reported version always matches the real release.
#
#   make build         # build every binary into $(BINDIR)
#   make install       # alias for build (BINDIR defaults to ~/bin)
#   make signer        # build a single binary
#   make test          # go test -race ./...
#   make fmt vet       # gofmt -l / go vet
#   make version       # print the version that would be embedded
#   make dist          # release tarball: binaries + deploy/ + example configs
#   make docs-gen      # regenerate docs/reference/ from code
#   make docs-check    # gen + drift checks + strict site build (CI gate, run before pushing)
#   make docs-serve    # live-preview the site at 127.0.0.1:8000

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG     := github.com/luisgf/ssh-broker/internal/version
LDFLAGS := -X $(PKG).Version=$(VERSION)
BINDIR  ?= $(HOME)/bin
CMDS    := signer broker broker-ctl mcp-broker mcp-broker-http control-plane
# MkDocs runner: prefer a local mkdocs, else fall back to `python3 -m mkdocs`.
MKDOCS  ?= $(shell command -v mkdocs 2>/dev/null || echo "python3 -m mkdocs")

.PHONY: build install $(CMDS) test fmt vet version clean dist docs docs-gen docs-serve docs-check

build: $(CMDS)
install: build

$(CMDS):
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$@ ./cmd/$@

test:
	go test -race ./...

fmt:
	gofmt -l .

vet:
	go vet ./...

version:
	@echo $(VERSION)

clean:
	rm -f $(addprefix $(BINDIR)/,$(CMDS))
	rm -rf dist

# Release tarball for deploy/install.sh: dist/ssh-broker-<version>/ with the
# binaries under bin/, the deploy artifacts (systemd units + installer) and
# the example configs the installer seeds /etc/ssh-broker from.
DISTDIR := dist/ssh-broker-$(VERSION)

dist:
	rm -rf $(DISTDIR)
	mkdir -p $(DISTDIR)/bin
	$(MAKE) build BINDIR=$(abspath $(DISTDIR)/bin)
	cp -r deploy $(DISTDIR)/
	cp signer.example.json control-plane.example.json config.example.json \
	   broker-ctl.example.json LICENSE README.md $(DISTDIR)/
	tar -C dist -czf dist/ssh-broker-$(VERSION).tar.gz ssh-broker-$(VERSION)
	@echo "dist/ssh-broker-$(VERSION).tar.gz"

# ── Documentation (GitHub Pages, with anti-drift generation) ──────────────────

# Regenerate the code-derived reference pages from the actual routes, MCP tool
# schemas, config structs, and CLI.
docs-gen:
	go run ./tools/docgen

# Build the static site, failing on a broken link or anchor (strict).
docs: docs-gen
	$(MKDOCS) build --strict

# Full anti-drift gate (what CI runs): regenerate the reference and fail if it
# differs from what's committed; validate the example configs against the structs;
# build the site strictly.
docs-check: docs-gen
	@git diff --exit-code docs/reference \
	  || { echo "docs/reference is stale — commit the regenerated files (make docs-gen)"; exit 1; }
	go test ./cmd/signer/ ./cmd/control-plane/ ./cmd/broker-ctl/ ./internal/broker/ -run ExampleConfig
	$(MKDOCS) build --strict

# Live preview at http://127.0.0.1:8000 (regenerates first).
docs-serve: docs-gen
	$(MKDOCS) serve
