#!/usr/bin/env bash
# Lab e2e de identidad IdP por agente (#121): Keycloak + OAuth2 client_credentials.
#
# Levanta Keycloak en Docker, crea un realm con un cliente de service account
# (client_credentials) y los TRES mappers no obvios, obtiene un access token y
# demuestra que el token queda listo para el frontend HTTP de infrabroker:
#
#   1. sub = UUID del service account, azp = client id  → por eso user_claim=azp
#      (la identidad de auditoría/RBAC es el id del cliente, no el UUID opaco).
#   2. aud = "infrabroker" (audience mapper). Sin él Keycloak emite aud="account"
#      y el verifier lo rechaza.
#   3. groups presente (group-membership mapper sobre el service account). Sin él
#      el groups_claim del verifier es fail-closed y rechaza el token.
#
# Requisitos: docker, curl, jq. No necesita compilar infrabroker: el verifier ya
# es claim-agnostic (ver internal/oauth/verifier_test.go, casos ClientCredentials).
# Al final imprime el bloque "oauth" que pondrías en la config de mcp-broker-http.
set -euo pipefail

KC_IMAGE="quay.io/keycloak/keycloak:26.0"
KC_NAME="infrabroker-oauth-lab"
KC_PORT=8080
# Published on loopback only: the script never talks to Keycloak from anywhere
# but this host, and the bootstrap admin console must not be reachable on the LAN.
KC_BIND="127.0.0.1"
KC_URL="http://localhost:${KC_PORT}"
REALM="infrabroker"
CLIENT="agent-ci-runner"        # the client id → the agent's identity (via azp)
AUDIENCE="infrabroker"          # this resource server (the verifier's expected aud)
GROUP="ci"                      # RBAC group the agent belongs to
ADMIN=admin
# The bootstrap admin password is only ever used inside this script (kcadm login
# below), so generate it per run instead of shipping the well-known admin/admin.
ADMIN_PW=$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')
# Exported so `docker run -e NAME` / `docker exec -e NAME` read it from the environment:
# the secrets never travel in argv (ps-visible).
export KC_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PW"
KCADM="/opt/keycloak/bin/kcadm.sh"

for bin in docker curl jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "falta '$bin'"; exit 1; }
done

SECRET_FILE=""
cleanup() { docker rm -f "$KC_NAME" >/dev/null 2>&1 || true; [ -z "$SECRET_FILE" ] || rm -f "$SECRET_FILE"; }
trap cleanup EXIT

echo "== 1. Keycloak ($KC_IMAGE) en ${KC_BIND}:$KC_PORT =="
docker rm -f "$KC_NAME" >/dev/null 2>&1 || true
docker run -d --name "$KC_NAME" -p "${KC_BIND}:${KC_PORT}:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME="$ADMIN" -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  "$KC_IMAGE" start-dev >/dev/null

echo -n "   esperando a Keycloak"
for _ in $(seq 1 60); do
  if curl -fsS "${KC_URL}/realms/master/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo " listo"; break
  fi
  echo -n "."; sleep 2
done
curl -fsS "${KC_URL}/realms/master/.well-known/openid-configuration" >/dev/null 2>&1 || { echo " Keycloak no arrancó"; exit 1; }

kc() { docker exec "$KC_NAME" "$KCADM" "$@"; }

echo "== 2. realm + cliente service-account + 3 mappers =="
# The password is read from the container environment by the inner shell, never put in argv.
docker exec -e KC_BOOTSTRAP_ADMIN_PASSWORD "$KC_NAME" sh -c \
  "$KCADM config credentials --server http://localhost:8080 --realm master --user $ADMIN"' --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"' >/dev/null
kc create realms -s realm="$REALM" -s enabled=true >/dev/null

# Confidential client with service accounts enabled = the OAuth2 client_credentials grant.
kc create clients -r "$REALM" \
  -s clientId="$CLIENT" -s enabled=true -s publicClient=false \
  -s standardFlowEnabled=false -s directAccessGrantsEnabled=false \
  -s serviceAccountsEnabled=true >/dev/null
CID=$(kc get clients -r "$REALM" -q clientId="$CLIENT" --fields id --format csv --noquotes | tr -d '\r')
SECRET=$(kc get "clients/${CID}/client-secret" -r "$REALM" --fields value --format csv --noquotes | tr -d '\r')

# (2a) Audience mapper — put "infrabroker" in aud (else aud=account → rejected).
kc create "clients/${CID}/protocol-mappers/models" -r "$REALM" \
  -s name=audience-infrabroker -s protocol=openid-connect \
  -s protocolMapper=oidc-audience-mapper \
  -s 'config."included.custom.audience"='"$AUDIENCE" \
  -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' >/dev/null

# (2b) Group + group-membership mapper — emit the groups claim (else fail-closed).
kc create groups -r "$REALM" -s name="$GROUP" >/dev/null
kc create "clients/${CID}/protocol-mappers/models" -r "$REALM" \
  -s name=groups -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."claim.name"=groups' -s 'config."full.path"=false' \
  -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' \
  -s 'config."userinfo.token.claim"=false' >/dev/null

# (2c) Put the client's service-account user in the group.
SA_UID=$(kc get "clients/${CID}/service-account-user" -r "$REALM" --fields id --format csv --noquotes | tr -d '\r')
GID=$(kc get groups -r "$REALM" -q search="$GROUP" --fields id --format csv --noquotes | tr -d '\r')
kc update "users/${SA_UID}/groups/${GID}" -r "$REALM" -n >/dev/null

echo "== 3. token vía client_credentials =="
# The client secret goes through a 0600 scratch file (removed by the EXIT trap), not argv.
SECRET_FILE=$(umask 077; mktemp "${TMPDIR:-/tmp}/infrabroker-oauth-secret.XXXXXX")
printf '%s' "$SECRET" > "$SECRET_FILE"
TOKEN=$(curl -fsS "${KC_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id="$CLIENT" \
  --data-urlencode "client_secret@${SECRET_FILE}" | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "no se obtuvo token"; exit 1; }

# Decode the JWT payload (base64url) without verifying — this is a demo of claims.
payload=$(echo "$TOKEN" | cut -d. -f2)
case $(( ${#payload} % 4 )) in 2) payload="${payload}==";; 3) payload="${payload}=";; esac
CLAIMS=$(echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)

echo "$CLAIMS" | jq '{sub, azp, aud, groups, scope}'

echo "== 4. aserciones (los 3 gotchas) =="
fail=0
assert() { if eval "$2"; then echo "  ✔ $1"; else echo "  ✘ $1"; fail=1; fi; }
assert "azp = client id ($CLIENT)  → user_claim=azp"        '[ "$(echo "$CLAIMS" | jq -r .azp)" = "$CLIENT" ]'
assert "sub ≠ azp (sub es el UUID del service account)"      '[ "$(echo "$CLAIMS" | jq -r .sub)" != "$CLIENT" ]'
assert "aud contiene \"$AUDIENCE\" (audience mapper)"        'echo "$CLAIMS" | jq -e --arg a "$AUDIENCE" '"'"'([.aud]|flatten)|index($a)'"'"' >/dev/null'
assert "groups contiene \"$GROUP\" (group mapper)"           'echo "$CLAIMS" | jq -e --arg g "$GROUP" '"'"'(.groups//[])|index($g)'"'"' >/dev/null'
[ "$fail" = 0 ] || { echo "FALLO: el realm no emite las claims esperadas"; exit 1; }

cat <<EOF

== 5. config para mcp-broker-http ==
Pon esto en la config del frontend HTTP y el token de arriba será aceptado, con
la identidad = "$CLIENT" y grupos = ["$GROUP"] (RBAC por-agente, igual que un humano):

  "oauth": {
    "issuer":       "${KC_URL}/realms/${REALM}",
    "audience":     "${AUDIENCE}",
    "user_claim":   "azp",
    "groups_claim": "groups"
  }

Obtén un token con:
  curl -s ${KC_URL}/realms/${REALM}/protocol/openid-connect/token \\
    -d grant_type=client_credentials -d client_id=${CLIENT} -d client_secret=<secret>

OK: identidad IdP por agente vía client_credentials verificada contra Keycloak real.
EOF
