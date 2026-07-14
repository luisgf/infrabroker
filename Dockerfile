# Built by goreleaser (see .goreleaser.yaml): the context already contains
# the seven prebuilt static binaries for the target platform — no compilation
# happens here, so the image binaries are bit-identical to the release archives.
#
# distroless/static ships CA roots (outbound TLS to the signer / OIDC / Azure
# Key Vault) and a nonroot user (uid 65532), and nothing else: no shell, no
# package manager. The broker's SSH client is pure Go — no openssh needed.
FROM gcr.io/distroless/static-debian12:nonroot

# goreleaser (dockers_v2) lays the prebuilt binaries out per platform
# (linux/amd64/..., linux/arm64/...) in the build context.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/infrabroker \
     $TARGETPLATFORM/signer $TARGETPLATFORM/broker $TARGETPLATFORM/broker-ctl \
     $TARGETPLATFORM/mcp-broker $TARGETPLATFORM/mcp-broker-http \
     $TARGETPLATFORM/control-plane /usr/local/bin/

USER nonroot

# stdio MCP frontend by default (what MCP clients launch). Kept as the legacy
# `mcp-broker` name so server.json (which appends `-config <path>`) stays valid;
# `infrabroker serve-mcp` is the unified equivalent. The other binaries are
# selected with --entrypoint, e.g. --entrypoint /usr/local/bin/infrabroker.
ENTRYPOINT ["/usr/local/bin/mcp-broker"]
