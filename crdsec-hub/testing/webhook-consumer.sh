#!/bin/bash

# Minimal debug receiver: terminates TLS and dumps whatever raw bytes it
# receives (the full HTTP request - method line, headers, JSON body) to
# stdout. Reuses the hub's existing leaf cert/key rather than generating
# new ones just for this. Doesn't send a real HTTP response back, so the
# crowdsec http-notification-plugin will likely time out waiting for one -
# that's expected and harmless here, we only care about what it sent.
#
# Listens on the Docker host itself (see crdsec-hub's docker-compose.yml
# extra_hosts for host.docker.internal, and config/notifications/http.yaml
# for the matching url:). Temporary debug tool, not part of normal
# operation.
#
# WEBHOOK_PORT env var overrides the default port (19999) - must match
# whatever's configured in http.yaml's "url:".

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WEBHOOK_PORT="${WEBHOOK_PORT:-19999}"

exec openssl s_server \
  -accept "$WEBHOOK_PORT" \
  -cert "${SCRIPT_DIR}/../tls/tls.crt" \
  -key "${SCRIPT_DIR}/../tls/tls.key"
