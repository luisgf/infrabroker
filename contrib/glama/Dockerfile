# Introspection-only image for the Glama MCP index (https://glama.ai/mcp/servers).
#
# Glama scores a server by BUILDING this Dockerfile, STARTING the container and
# issuing an MCP introspection request (initialize + tools/list). infrabroker's
# real entrypoint needs a signer/PKI or a full local config, so it cannot start
# bare. This image starts mcp-broker in a *zero-host local mode* with throwaway
# credentials generated AT BUILD TIME (never committed, never reused): an SSH CA
# that signs certificates for zero hosts and an audit seed for a throwaway log.
# It exposes the exact tool surface (ssh_execute, ssh_session_*, ssh_*_file,
# ssh_list_servers) so introspection passes — and can do nothing else, because
# there is no host to reach and no signer. Do NOT use this image to run the
# broker; the real images are ghcr.io/luisgf/infrabroker (see docs/CONTAINERS.md).
#
# Build context is the repo root:
#   docker build -f contrib/glama/Dockerfile -t infrabroker-introspect .
#   docker run --rm -i infrabroker-introspect   # then speaks MCP over stdio

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/mcp-broker ./cmd/mcp-broker

# Generate the throwaway local-mode config + credentials. openssh-client gives us
# ssh-keygen for the Ed25519 CA key; the audit seed is 32 random bytes.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
 && mkdir -p /introspect/pki \
 && ssh-keygen -t ed25519 -N '' -C 'glama-introspect-ca' -f /introspect/pki/ssh_ca >/dev/null \
 && head -c 32 /dev/urandom > /introspect/pki/audit.seed \
 && printf '%s\n' '{' \
      '  "ca_key": "/introspect/pki/ssh_ca",' \
      '  "audit_key": "/introspect/pki/audit.seed",' \
      '  "audit_log": "/tmp/introspect-audit.log",' \
      '  "max_ttl_seconds": 300,' \
      '  "hosts": {}' \
      '}' > /introspect/config.json

# Same runtime as the release image: distroless static, nonroot, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-broker /usr/local/bin/mcp-broker
COPY --from=build --chown=65532:65532 /introspect /introspect
USER nonroot
ENTRYPOINT ["/usr/local/bin/mcp-broker", "-config", "/introspect/config.json"]
