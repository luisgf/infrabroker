# ssh-broker build. The version is derived from the git tag and injected into
# the binaries so the reported version always matches the real release.
#
#   make build         # build every binary into $(BINDIR)
#   make install       # alias for build (BINDIR defaults to ~/bin)
#   make signer        # build a single binary
#   make test          # go test -race ./...
#   make fmt vet       # gofmt -l / go vet
#   make version       # print the version that would be embedded

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG     := github.com/luisgf/ssh-broker/internal/version
LDFLAGS := -X $(PKG).Version=$(VERSION)
BINDIR  ?= $(HOME)/bin
CMDS    := signer broker broker-ctl mcp-broker mcp-broker-http control-plane

.PHONY: build install $(CMDS) test fmt vet version clean

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
