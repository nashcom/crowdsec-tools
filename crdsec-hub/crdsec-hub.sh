#!/bin/bash

###########################################################################
#                                                                         #
# crdsec-hub - self-hosted central CrowdSec hub container                 #
#                                                                         #
# (C) Copyright Daniel Nashed/NashCom 2026                                #
#                                                                         #
# Licensed under the Apache License, Version 2.0 (the "License");         #
# you may not use this file except in compliance with the License.        #
# You may obtain a copy of the License at                                 #
#                                                                         #
#      http://www.apache.org/licenses/LICENSE-2.0                         #
#                                                                         #
# Unless required by applicable law or agreed to in writing, software     #
# distributed under the License is distributed on an "AS IS" BASIS,       #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.#
# See the License for the specific language governing permissions and     #
# limitations under the License.                                          #
#                                                                         #
# Version 0.9.4                                                           #
#                                                                         #
# Purpose:                                                                #
#                                                                         #
#   Bring up and operate a container running a central CrowdSec           #
#   instance (LAPI + decision database) that remote crdsectl agents       #
#   (see ../crdsectl) can report to and query decisions from, instead     #
#   of each agent running fully standalone.                               #
#                                                                         #
# This is NOT the CrowdSec Console (app.crowdsec.net) - that is a         #
# hosted SaaS product with no self-hosted equivalent. This is a           #
# self-hosted central LAPI, a different and separate concept that         #
# happens to serve a similar "one place to see everything" purpose.       #
#                                                                         #
# Uses CrowdSec's own official image (crowdsecurity/crowdsec, see         #
# docker-compose.yml) rather than a custom-built one: it already runs     #
# crowdsec directly as PID 1 with no systemd or package-manager           #
# install step needed, unlike ../crdsectl's agent test image, which       #
# deliberately mirrors a real "apt install crowdsec" including its        #
# systemd dependency.                                                     #
#                                                                         #
# Runs on the host, not inside the container: "up"/"down" delegate to     #
# docker compose; the machine/bouncer/status commands use "docker         #
# exec" against the running container.                                    #
#                                                                         #
###########################################################################

CRDSEC_HUB_VERSION="0.9.4"

CONTAINER_NAME="crdsec-hub"

HTTP_NOTIF_FILE="$(dirname "$0")/config/notifications/http.yaml"

# Sourced (not just read by docker compose) so the messages below can
# print a real, usable URL instead of a placeholder. Keep in sync with
# docker-compose.yml's ${VAR:-default} usage for the same names.
ENV_FILE="$(dirname "$0")/.env"

if [ -r "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

HUB_HOST="${HUB_HOST:-localhost}"
NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-8443}"


###############################################################################
# Generic helpers
###############################################################################

print_delim()
{
  echo "--------------------------------------------------------------------------------"
}


log_err()
{
  echo
  echo "Error: $*"
  echo
}


have_command()
{
  command -v "$1" >/dev/null 2>&1
}


require_docker()
{
  if ! have_command docker; then
    log_err "docker command not found."
    return 1
  fi
}


container_running()
{
  docker ps --filter "name=^${CONTAINER_NAME}\$" --filter "status=running" --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}\$"
}


require_running_container()
{
  require_docker || return 1

  if ! container_running; then
    log_err "Container '${CONTAINER_NAME}' is not running. Run '$0 up' first."
    return 1
  fi
}


dexec()
{
  docker exec "$CONTAINER_NAME" "$@"
}


###############################################################################
# Container lifecycle (docker compose)
###############################################################################

compose()
{
  require_docker || return 1
  ( cd "$(dirname "$0")" && docker compose "$@" )
}


bring_up()
{
  require_docker || return 1

  # docker-compose.yml owns/creates crowdsec-net itself (not external:true)
  # - no manual pre-step needed here. It's shared with ../crdsectl/run-install-test-container.sh's
  # agent test container when that's run with NETWORK_MODE=bridge instead
  # of its default --network host.
  echo
  echo "Starting ${CONTAINER_NAME} via docker compose, publishing HTTPS port ${NGINX_HTTPS_PORT} (nginx) ..."
  echo
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"
  local fresh_config="no"
  [ -e "$profiles_file" ] || fresh_config="yes"

  compose up -d || return 1

  # Only apply the progressive-ban-by-default nudge on a genuinely fresh
  # config (profiles.yaml didn't exist before this "up") - "up" is a
  # routine command (reboots, host maintenance), unlike crdsectl's
  # explicit "update", so re-asserting it on every single call would
  # silently undo an admin's own choice far too often to be reasonable.
  if [ "$fresh_config" = "yes" ]; then
    # profiles.yaml is seeded by CrowdSec's own entrypoint into the
    # (initially empty) bind-mounted config/ dir - usually near-instant,
    # but give it a few seconds before giving up silently.
    local waited=0
    while [ ! -e "$profiles_file" ] && [ "$waited" -lt 5 ]; do
      sleep 1
      waited=$((waited + 1))
    done

    if enable_progressive_default; then
      echo
      echo "Restarting crowdsec to apply..."
      compose restart crowdsec
    fi
  fi

  echo
  echo "Container is up. Run '$0 status' to check it, or '$0 shell' for a shell inside it."
}


bring_down()
{
  compose down
  echo "Container '${CONTAINER_NAME}' stopped and removed. The data/config volumes were left in place (see docker-compose.yml)."
}


open_shell()
{
  require_running_container || return 1
  docker exec -it "$CONTAINER_NAME" sh
}


###############################################################################
# Status
###############################################################################

show_status()
{
  require_docker || return 1

  echo
  print_delim
  echo "crdsec-hub Status"
  print_delim
  echo
  printf "%-24s :  %s\n" "crdsec-hub version" "$CRDSEC_HUB_VERSION"
  echo

  if container_running; then
    printf "%-24s :  %s\n" "Container" "running"
  else
    printf "%-24s :  %s\n" "Container" "not running"
    echo
    return 0
  fi

  local crowdsec_version
  crowdsec_version=$(dexec cscli version 2>/dev/null | head -1)
  printf "%-24s :  %s\n" "CrowdSec" "${crowdsec_version:-not reachable}"

  printf "%-24s :  %s\n" "Hub host" "$HUB_HOST"
  printf "%-24s :  %s\n" "Hub HTTPS port (nginx)" "$NGINX_HTTPS_PORT"
  printf "%-24s :  %s\n" "Hub URL" "https://${HUB_HOST}:${NGINX_HTTPS_PORT}"
  echo
  printf "%-24s :  %s\n" "Default ban duration" "$(format_ban_duration || echo 'not set')"
  printf "%-24s :  %s\n" "Progressive ban" "$(format_progressive_state || echo 'unknown')"
  echo
}


###############################################################################
# Alerts / decisions
###############################################################################

list_alerts()
{
  require_running_container || return 1
  dexec cscli alerts list
}


list_decisions()
{
  require_running_container || return 1
  dexec cscli decisions list
}


show_metrics()
{
  require_running_container || return 1
  dexec cscli metrics
}


# Since this runs as a raw Docker container (PID 1, no systemd - unlike
# ../crdsectl's test image), there's no "journalctl -u crowdsec" here;
# "docker logs" is the container-level equivalent, and covers the plugin
# loading errors that container-internal cscli commands can't see (a
# broken notification-plugin config, for example, is logged by the
# crowdsec process itself at startup, before cscli would ever be usable
# to ask about it).
show_log()
{
  local lines="${1:-100}"

  case "$lines" in
    ''|*[!0-9]*)
      log_err "Log line count must be numeric."
      return 1
      ;;
  esac

  require_running_container || return 1
  docker logs --tail "$lines" "$CONTAINER_NAME"
}


# "logs" (no line count) is "log"'s full-history counterpart, not a bare
# alias for it - full since-container-start output, no --tail limit.
show_full_log()
{
  require_running_container || return 1
  docker logs "$CONTAINER_NAME"
}


# Hub-side manual ban/unban, mirroring ../crdsectl/crdsectl.sh's own
# block/unblock (same "cscli decisions add/delete --ip" underneath). Useful
# for banning an IP hub-wide from one place without touching any single
# agent - every registered agent's bouncer picks it up on its next poll.
ban_ip()
{
  local ip="$1"
  local duration="$2"

  if [ -z "$ip" ]; then
    log_err "No IP address specified."
    return 1
  fi

  require_running_container || return 1

  if [ -n "$duration" ]; then
    dexec cscli decisions add --ip "$ip" --duration "$duration"
  else
    dexec cscli decisions add --ip "$ip"
  fi
}


unban_ip()
{
  local ip="$1"

  if [ -z "$ip" ]; then
    log_err "No IP address specified."
    return 1
  fi

  require_running_container || return 1
  dexec cscli decisions delete --ip "$ip"
}


###############################################################################
# Machine / bouncer registration
###############################################################################

add_machine()
{
  local name="$1"
  shift

  local force="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --force|-f)
        force="yes"
        ;;
      *)
        log_err "Unknown option: '$1'"
        return 1
        ;;
    esac
    shift
  done

  if [ -z "$name" ]; then
    log_err "No machine name specified."
    return 1
  fi

  require_running_container || return 1

  # Deleting a name that doesn't exist errors - ignored on purpose, this
  # is a "clear the way" pre-step, not something that itself needs to
  # succeed. Without --force, a name collision surfaces as cscli's own
  # "already exists" error below, same as always.
  if [ "$force" = "yes" ]; then
    dexec cscli machines delete "$name" >/dev/null 2>&1
  fi

  echo
  echo "Registering machine '${name}'. Copy the printed credentials into that"
  echo "agent's /etc/crowdsec/local_api_credentials.yaml."
  echo
  # -f - prints credentials to stdout instead of writing them into this
  # container's own local_api_credentials.yaml, which is unrelated - that
  # file is for crowdsec's own local watcher, not for remote agents, and
  # writing to it would conflict with whatever the image already put there.
  # -u overrides the printed "url:" with our actual external address -
  # cscli otherwise echoes api.server.listen_uri verbatim (0.0.0.0:8080 in
  # this image), which is a bind address, not something a remote agent
  # could ever connect to, and has no idea nginx is in front of it.
  dexec cscli machines add "$name" --auto -f - --url "https://${HUB_HOST}:${NGINX_HTTPS_PORT}"
}


list_machines()
{
  require_running_container || return 1
  dexec cscli machines list
}


add_bouncer()
{
  local name="$1"
  shift

  local force="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --force|-f)
        force="yes"
        ;;
      *)
        log_err "Unknown option: '$1'"
        return 1
        ;;
    esac
    shift
  done

  if [ -z "$name" ]; then
    log_err "No bouncer name specified."
    return 1
  fi

  require_running_container || return 1

  if [ "$force" = "yes" ]; then
    dexec cscli bouncers delete "$name" >/dev/null 2>&1
  fi

  echo
  echo "Registering bouncer '${name}'. The printed key is shown once - copy it"
  echo "into the remote bouncer's config as:"
  echo "  api_url: https://${HUB_HOST}:${NGINX_HTTPS_PORT}"
  echo "  api_key: from the output below"
  echo
  dexec cscli bouncers add "$name"
}


list_bouncers()
{
  require_running_container || return 1
  dexec cscli bouncers list
}


# Combines add_machine + add_bouncer into the one call an agent registration
# actually needs, and - since both credentials are captured here rather
# than left to the eye - prints a ready-to-paste "crdsectl register" line,
# mirroring that command's own name/shape on the agent side (this produces
# what that one consumes). add_machine/add_bouncer stay available
# separately for re-issuing just one credential without touching the other.
register_machine()
{
  local name="$1"
  shift

  local force="no"
  while [ $# -gt 0 ]; do
    case "$1" in
      --force|-f)
        force="yes"
        ;;
      *)
        log_err "Unknown option: '$1'"
        return 1
        ;;
    esac
    shift
  done

  if [ -z "$name" ]; then
    log_err "No name specified."
    return 1
  fi

  require_running_container || return 1

  if [ "$force" = "yes" ]; then
    dexec cscli machines delete "$name" >/dev/null 2>&1
    dexec cscli bouncers delete "$name" >/dev/null 2>&1
  fi

  echo
  echo "Registering machine '${name}'..."
  # 2>&1: "cscli machines add -f -" writes its output (the confirmation
  # AND the url/login/password block) to stderr, not stdout - confirmed
  # live (2026-08-22) via the raw-bytes diagnostic below, which showed
  # machine_output captured completely empty despite the credentials
  # printing correctly to the terminal (stderr passing straight through,
  # uncaptured, while stdout-only capture got nothing). "cscli bouncers
  # add" behaves differently (its key does land on stdout) - inconsistent
  # between the two cscli subcommands, not a bug in the capture logic.
  local machine_output
  machine_output=$(dexec cscli machines add "$name" --auto -f - --url "https://${HUB_HOST}:${NGINX_HTTPS_PORT}" 2>&1)
  local machine_rc=$?
  echo "$machine_output"

  if [ $machine_rc -ne 0 ]; then
    log_err "Failed to register machine '${name}'."
    return 1
  fi

  echo
  echo "Registering bouncer '${name}'..."
  local bouncer_output
  bouncer_output=$(dexec cscli bouncers add "$name" 2>&1)
  local bouncer_rc=$?
  echo "$bouncer_output"

  if [ $bouncer_rc -ne 0 ]; then
    log_err "Failed to register bouncer '${name}'. The machine credentials above are still valid - retry the bouncer alone with 'addbouncer ${name}'."
    return 1
  fi

  # Strip ANSI color escapes (cscli output through docker exec can carry
  # them even without a TTY) before parsing - first failed live test
  # (2026-08-22) parsed nothing despite matching the same text exactly when
  # tested standalone, most likely explained by exactly this.
  local machine_clean bouncer_clean
  machine_clean=$(printf '%s\n' "$machine_output" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g')
  bouncer_clean=$(printf '%s\n' "$bouncer_output" | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g')

  # search-anywhere-in-line (not line-start-anchored) so a stray leading
  # character survives being wrong without breaking the match entirely.
  local password
  password=$(printf '%s\n' "$machine_clean" | awk '/password:/{ sub(/.*password:[ \t]*/, ""); print; exit }')

  # The key line is the only non-empty line that isn't the "API key for..."
  # header or the "Please keep..." footer - trimmed of its leading indent.
  local bouncer_key
  bouncer_key=$(printf '%s\n' "$bouncer_clean" | awk 'NF && index($0,"API key")==0 && index($0,"Please keep")==0 { gsub(/^[ \t]+|[ \t]+$/, ""); print; exit }')

  echo
  print_delim

  if [ -z "$password" ] || [ -z "$bouncer_key" ]; then
    echo "Could not parse credentials automatically (password: ${password:-<empty>}, bouncer_key: ${bouncer_key:-<empty>})."
    echo "Raw bytes, for diagnosis:"
    printf '%s\n' "$machine_clean" | cat -A
    printf '%s\n' "$bouncer_clean" | cat -A
  fi

  if [ -n "$password" ] && [ -n "$bouncer_key" ]; then
    echo "Run this on the agent:"
    echo
    echo "  crdsectl trust <hub-ca-cert-path>   # only if this hub uses a self-signed CA"
    echo "  crdsectl register https://${HUB_HOST}:${NGINX_HTTPS_PORT} ${name} ${password} ${bouncer_key}"
  else
    echo "Copy the credentials above manually into:"
    echo "  crdsectl register <hub-url> ${name} <password> <bouncer-key>"
  fi

  echo
}


###############################################################################
# OTLP notification configuration
###############################################################################

# Placeholders (__OTLP_URL__/__OTLP_SKIP_TLS__) get substituted after
# generation, rather than interpolating bash variables directly into the
# heredoc - the Go template body below is full of literal "$" (Go template
# variables like $alert/$decision), which an unquoted/interpolating heredoc
# would try to expand as shell variables. The headers block is different -
# it's plain YAML with no "$" conflict, but its line count varies (zero or
# more --header flags), so it's assembled separately in bash and printed
# between two static heredoc chunks instead of forced through a placeholder.
generate_http_notification()
{
  local headers_block="$1"

  cat <<'EOF'
# ---------------------------------------------------------------------------
# crdsec-hub OTLP notification (http plugin)
# Managed by crdsec-hub. Do not manually edit - use "crdsec-hub.sh otlp <url>"
# to regenerate. See ../README.md's "OpenTelemetry event export (OTLP)"
# section for the field mapping, severity rules, and known caveats.
# ---------------------------------------------------------------------------

type: http          # Don't change
name: http_default  # Must match the registered plugin in profiles.yaml

# One of "trace", "debug", "info", "warn", "error", "off". debug/trace logs
# the actual outgoing request body - useful while wiring up a new endpoint,
# visible via "crdsec-hub.sh log".
log_level: debug

# group_wait:      # Time to wait collecting alerts before relaying, eg "30s"
# group_threshold: # Alert count that triggers a message before group_wait expires
# max_retry:       # Retry attempts on delivery error
# timeout:         # Response timeout before considering an attempt failed

# Emits a real, minimal OTLP/HTTP envelope (resourceLogs[].scopeLogs[]
# .logRecords[]) matching the actual wire shape used by the reference
# Domino->OTLP pipeline (domfwd, a separate C-API servertask) - NOT a full
# typed-attribute rewrite. Confirmed by reading domfwd's own source
# (2026-08-22): it does NOT map each field into a typed OTLP AnyValue
# attribute; it builds the same flat "OTLP-flavored" JSON already used for
# Domino event logs (snake_case fields, flat resource/attributes objects)
# exactly as before, then embeds that ENTIRE flat JSON as a single JSON
# *string* inside logRecords[0].body.stringValue - the outer envelope only
# carries routing-level fields (time/severity/a single "service.name"
# resource attribute), everything CrowdSec-specific stays in the flat inner
# JSON, unchanged in shape from the original design.
#
# A flat body with NO envelope at all was confirmed live (2026-08-22) to be
# rejected by Loki's real OTLP receiver - fails Content-Type sniffing
# first, and once that's fixed, fails again with "at least one valid stream
# is required for ingestion" (Loki looks for resourceLogs and finds none).
# A hand-built minimal envelope posted directly via curl (../testing/test-otlp.sh)
# confirmed the receiver accepts a real envelope (204) - domfwd's own
# pattern (envelope + flat-JSON-as-string body) is the one actually proven
# to work end to end against this same Loki instance.
#
# The inner flat JSON is built via Sprig's "dict" (not hand-written text
# interpolation like the old flat template) so it can be piped through
# "toJson" TWICE: once to get the compact flat JSON as a Go string, once
# more to embed that string, correctly quote-escaped, as the outer
# envelope's "stringValue". Pointer fields (Origin/Simulated - see below)
# can go into the dict raw, without an inner toJson each - encoding/
# json.Marshal (what toJson wraps) dereferences pointers anywhere in a
# value tree, not just at the top level, same mechanism already proven for
# the leaf-level "| toJson" calls this template used before. Live-verified
# end to end (2026-08-22) via "cscli notifications test" against the real
# target Loki instance - clean 204, all fields present and correctly typed
# on the first try.
#
# Assumes exactly one decision per alert ("index .Decisions 0") - true for
# every payload observed so far; would need a range loop if that changes.
#
# Severity: WARN for a genuine enforced detection, INFO for a simulated or
# manually cscli-originated decision. Origin/Simulated are Go pointer types
# (*string/*bool) - compare them via "toJson", not "printf": printf does not
# dereference a pointer-to-scalar the way toJson (via encoding/json.Marshal)
# does, and silently compares against garbage instead of the real value.
#
# GetMeta(alert, "service") can return an empty slice - confirmed live via
# "cscli notifications test" (its synthetic alert has no "service" meta),
# not just a hypothetical future scenario. "index ... 0" on that panics the
# whole plugin ("reflect: slice index out of range"), so the length is
# checked first and "crowdsec.service" falls back to "" when absent.
format: |
  {{ range . -}}
  {{ $alert := . -}}
  {{ $decision := index .Decisions 0 -}}
  {{ $severityNumber := 13 -}}
  {{ $severityText := "WARN" -}}
  {{ if or (eq ($alert.Simulated | toJson) "true") (ne ($decision.Origin | toJson) "\"crowdsec\"") -}}
  {{ $severityNumber = 9 -}}
  {{ $severityText = "INFO" -}}
  {{ end -}}
  {{ $serviceMeta := GetMeta $alert "service" -}}
  {{ $service := "" -}}
  {{ if gt (len $serviceMeta) 0 -}}
  {{ $service = index $serviceMeta 0 -}}
  {{ end -}}
  {{ $timeUnixNano := printf "%d" ( $alert.StartAt | toDate "2006-01-02T15:04:05.999999999Z07:00" ).UnixNano -}}
  {{ $observedTimeUnixNano := printf "%d" now.UnixNano -}}
  {{ $innerBody := dict
       "time_unix_nano" $timeUnixNano
       "observed_time_unix_nano" $observedTimeUnixNano
       "severity_number" $severityNumber
       "severity_text" $severityText
       "body" $alert.Message
       "scope" (dict "name" "crowdsec.decision")
       "resource" (dict
         "service.name" "crowdsec"
         "service.instance.id" $alert.MachineID
         "host.name" Hostname)
       "attributes" (dict
         "crowdsec.decision.type" $decision.Type
         "crowdsec.decision.duration" $decision.Duration
         "crowdsec.decision.scenario" $decision.Scenario
         "crowdsec.decision.origin" $decision.Origin
         "crowdsec.decision.value" $decision.Value
         "crowdsec.decision.uuid" $decision.UUID
         "crowdsec.alert.uuid" $alert.UUID
         "crowdsec.service" $service
         "crowdsec.remediation" $alert.Remediation
         "crowdsec.simulated" $alert.Simulated
         "crowdsec.source.ip" $alert.Source.IP
         "crowdsec.source.scope" $alert.Source.Scope
         "crowdsec.source.country" $alert.Source.Cn
         "crowdsec.source.as_number" $alert.Source.AsNumber
         "crowdsec.source.as_name" $alert.Source.AsName
         "crowdsec.source.latitude" $alert.Source.Latitude
         "crowdsec.source.longitude" $alert.Source.Longitude
         "crowdsec.events_count" $alert.EventsCount) -}}
  {
    "resourceLogs": [
      {
        "resource": {
          "attributes": [
            { "key": "service.name", "value": { "stringValue": "crowdsec" } }
          ]
        },
        "scopeLogs": [
          {
            "scope": {
              "name": "crdsec-hub"
            },
            "logRecords": [
              {
                "timeUnixNano": {{ $timeUnixNano | toJson }},
                "observedTimeUnixNano": {{ $observedTimeUnixNano | toJson }},
                "severityNumber": {{ $severityNumber }},
                "severityText": {{ $severityText | toJson }},
                "body": { "stringValue": {{ $innerBody | toJson | toJson }} }
              }
            ]
          }
        ]
      }
    ]
  }
  {{ end -}}

# The plugin will make requests to this url.
url: __OTLP_URL__

# Any of the http verbs: "POST", "GET", "PUT"...
method: POST

EOF

  # The body is always JSON (this template only ever emits JSON) - the
  # CrowdSec http plugin does not set Content-Type on its own, and Loki's
  # OTLP receiver (and OTLP/HTTP receivers generally) reject requests with
  # no recognized Content-Type before even looking at the body. Confirmed
  # live (2026-08-22): "content type:  is not supported" (note the empty
  # value) from Loki. So this is a fixed header, not user-configurable via
  # --header/--token the way Authorization/X-Scope-OrgID are.
  echo "headers:"
  echo "  Content-Type: application/json"
  printf '%s' "$headers_block"

  cat <<'EOF'

skip_tls_verification: __OTLP_SKIP_TLS__
EOF
}


# Mirrors ../crdsectl/crdsectl.sh's check_hub_reachable (register pre-flight)
# but non-fatal here - an unreachable OTLP endpoint just means notifications
# won't deliver yet, not a broken agent registration, so it's fine to
# configure ahead of the endpoint actually existing.
check_otlp_endpoint()
{
  local url="$1"
  local insecure="$2"

  local curl_args=(--silent --show-error --max-time 10 -o /dev/null "$url")
  [ "$insecure" = "yes" ] && curl_args=(--insecure "${curl_args[@]}")

  curl "${curl_args[@]}"
}


# Enables http_default in profiles.yaml's default_ip_remediation profile -
# CrowdSec ships this commented out by default, and otlp never wired it
# up before, only managed the plugin's own config. Real decisions were
# silently never notifying because of this - "testnotif" alone couldn't
# catch it, since that bypasses profiles.yaml entirely. Only touches the
# first profile (default_range_remediation is left alone - unused here).
# Idempotent. Returns 0 if it changed something (needs a restart), 1 if
# there was nothing to do.
enable_profile_notification()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1

  local tmp
  tmp=$(mktemp) || return 1

  awk '
    BEGIN { doc = 1 }
    /^---$/ { doc++; print; next }
    doc == 1 && /^# notifications:$/ { sub(/^# /, ""); print; next }
    doc == 1 && /^#   - http_default/ { sub(/^#/, ""); print; next }
    { print }
  ' "$profiles_file" > "$tmp"

  if cmp -s "$tmp" "$profiles_file"; then
    rm -f "$tmp"
    return 1
  fi

  cp -a "$profiles_file" "${profiles_file}.bak"
  cp "$tmp" "$profiles_file"
  rm -f "$tmp"

  echo
  echo "[$profiles_file] enabled http_default in default_ip_remediation (was commented out - backup at ${profiles_file}.bak)"
  return 0
}


# Ban duration / progressive ban. Applied to both default_ip_remediation and
# default_range_remediation, kept in sync - unlike notifications above,
# range-scoped decisions (e.g. from console/community blocklists) are a
# real possibility here. A manual "profile" edit could still make them
# diverge - the getters below report both and format_*() shows
# "ip / range" whenever they differ, so a divergence is visible instead
# of silently only showing the ip value.

get_ban_duration_ip()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1
  awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_ip_remediation/ { found = 1 }
    found && /^[[:space:]]*duration:/ { print $2; exit }
  ' "$profiles_file"
}


get_ban_duration_range()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1
  awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_range_remediation/ { found = 1 }
    found && /^[[:space:]]*duration:/ { print $2; exit }
  ' "$profiles_file"
}


format_ban_duration()
{
  local ip_val range_val
  ip_val=$(get_ban_duration_ip) || return 1
  range_val=$(get_ban_duration_range)

  if [ "$ip_val" = "$range_val" ]; then
    echo "$ip_val"
  else
    echo "${ip_val} / ${range_val}"
  fi
}


get_progressive_state_ip()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1

  if awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_ip_remediation/ { found = 1 }
    found { print }
  ' "$profiles_file" | grep -q '^duration_expr:'; then
    echo "enabled"
  else
    echo "disabled"
  fi
}


get_progressive_state_range()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1

  if awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_range_remediation/ { found = 1 }
    found { print }
  ' "$profiles_file" | grep -q '^duration_expr:'; then
    echo "enabled"
  else
    echo "disabled"
  fi
}


format_progressive_state()
{
  local ip_val range_val
  ip_val=$(get_progressive_state_ip) || return 1
  range_val=$(get_progressive_state_range)

  if [ "$ip_val" = "$range_val" ]; then
    echo "$ip_val"
  else
    echo "${ip_val} / ${range_val}"
  fi
}


show_or_set_duration()
{
  local new_duration="$1"
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  if [ ! -e "$profiles_file" ]; then
    log_err "${profiles_file} not found."
    return 1
  fi

  if [ -z "$new_duration" ]; then
    echo "Default ban duration: $(format_ban_duration)"
    return 0
  fi

  if ! echo "$new_duration" | grep -Eq '^([0-9]+(h|m|s))+$'; then
    log_err "Invalid duration '${new_duration}' - expected a golang duration like '4h', '30m', '1h30m'."
    return 1
  fi

  local tmp
  tmp=$(mktemp) || return 1

  sed "s/^\([[:space:]]*duration: \).*/\1${new_duration}/" "$profiles_file" > "$tmp"

  if cmp -s "$tmp" "$profiles_file"; then
    rm -f "$tmp"
    echo "Default ban duration is already ${new_duration}."
    return 0
  fi

  cp -a "$profiles_file" "${profiles_file}.bak"
  cp "$tmp" "$profiles_file"
  rm -f "$tmp"

  echo "Default ban duration set to ${new_duration} (backup: ${profiles_file}.bak)."
  echo "Restarting crowdsec..."
  compose restart crowdsec
}


show_or_set_progressive()
{
  local action="$1"
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  if [ ! -e "$profiles_file" ]; then
    log_err "${profiles_file} not found."
    return 1
  fi

  if [ -z "$action" ]; then
    echo "Progressive ban: $(format_progressive_state)"
    return 0
  fi

  case "$action" in
    on|off) ;;
    *)
      log_err "Usage: $0 progressive [on|off]"
      return 1
      ;;
  esac

  local tmp
  tmp=$(mktemp) || return 1

  if [ "$action" = "on" ]; then
    sed 's/^#duration_expr:/duration_expr:/' "$profiles_file" > "$tmp"
  else
    sed 's/^duration_expr:/#duration_expr:/' "$profiles_file" > "$tmp"
  fi

  if cmp -s "$tmp" "$profiles_file"; then
    rm -f "$tmp"
    echo "Progressive ban is already ${action}."
    return 0
  fi

  cp -a "$profiles_file" "${profiles_file}.bak"
  cp "$tmp" "$profiles_file"
  rm -f "$tmp"

  echo "Progressive ban turned ${action} (backup: ${profiles_file}.bak)."
  echo "Restarting crowdsec..."
  compose restart crowdsec
}


# Silent, non-restarting variant used by bring_up() to enforce progressive
# ban as the shipped default on a genuinely fresh config only - bring_up()
# only calls this when profiles.yaml didn't exist before "up" ran, since
# "up" is routine (reboots, host maintenance) and re-asserting on every
# call would silently undo an admin's own choice far too often. Only
# touches duration_expr, never duration itself. Returns 0 if it changed
# something (caller must restart), 1 otherwise.
enable_progressive_default()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  [ -e "$profiles_file" ] || return 1

  local tmp
  tmp=$(mktemp) || return 1

  sed 's/^#duration_expr:/duration_expr:/' "$profiles_file" > "$tmp"

  if cmp -s "$tmp" "$profiles_file"; then
    rm -f "$tmp"
    return 1
  fi

  cp -a "$profiles_file" "${profiles_file}.bak"
  cp "$tmp" "$profiles_file"
  rm -f "$tmp"

  echo "profiles.yaml: progressive ban enabled by default (was disabled - backup at ${profiles_file}.bak)."
  return 0
}


edit_profiles()
{
  local profiles_file
  profiles_file="$(dirname "$0")/config/profiles.yaml"

  if [ ! -e "$profiles_file" ]; then
    log_err "${profiles_file} not found."
    return 1
  fi

  local editor="${EDITOR:-vi}"

  if ! have_command "$editor"; then
    log_err "Editor '${editor}' not found. Set \$EDITOR or install vi."
    return 1
  fi

  local pre_edit
  pre_edit=$(mktemp) || return 1
  cp -a "$profiles_file" "$pre_edit"

  "$editor" "$profiles_file"

  if cmp -s "$pre_edit" "$profiles_file"; then
    rm -f "$pre_edit"
    echo "No changes made."
    return 0
  fi

  # Only overwrite the persistent .bak once the edit is confirmed applied -
  # it's the last-known-good config, not a scratch file, so a no-op or a
  # failed restart must leave whatever backup was already there.
  local backup="${profiles_file}.bak"

  if ! container_running; then
    cp -a "$pre_edit" "$backup"
    rm -f "$pre_edit"
    echo "profiles.yaml updated (backup: ${backup})."
    echo "Hub is not running - this will take effect on the next '$0 up'."
    return 0
  fi

  echo "Restarting crdsec-hub to apply (config is only read at startup) ..."

  if ! compose restart crowdsec; then
    log_err "Restart failed. Restoring previous configuration."
    cp -a "$pre_edit" "$profiles_file"
    rm -f "$pre_edit"
    compose restart crowdsec
    return 1
  fi

  cp -a "$pre_edit" "$backup"
  rm -f "$pre_edit"
  echo "profiles.yaml updated (backup: ${backup})."
}


configure_otlp()
{
  local url="$1"
  shift

  local insecure="no"
  local headers=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --insecure)
        insecure="yes"
        ;;
      --token)
        if [ -z "$2" ]; then
          log_err "--token requires a value"
          return 1
        fi
        headers+=("Authorization: Bearer $2")
        shift
        ;;
      --header)
        if [ -z "$2" ]; then
          log_err "--header requires a value, eg --header \"X-Scope-OrgID: domino\""
          return 1
        fi
        case "$2" in
          *:*) ;;
          *)
            log_err "--header value must be \"Name: Value\", got: '$2'"
            return 1
            ;;
        esac
        headers+=("$2")
        shift
        ;;
      *)
        log_err "Unknown option: '$1'"
        return 1
        ;;
    esac
    shift
  done

  if [ -z "$url" ]; then
    log_err "No OTLP endpoint URL specified. Usage: $0 otlp <url> [--insecure] [--token <token>] [--header \"Name: Value\"]..."
    return 1
  fi

  case "$url" in
    https://*)
      ;;
    http://*)
      echo
      echo "Warning: '${url}' is not HTTPS - decision data would be sent unencrypted."
      ;;
    *)
      log_err "URL must start with http:// or https://"
      return 1
      ;;
  esac

  echo
  echo "Checking endpoint reachability: ${url} ..."
  check_otlp_endpoint "$url" "$insecure"
  local reach_rc=$?

  if [ "$reach_rc" -eq 60 ]; then
    echo "Warning: TLS certificate at '${url}' could not be validated. Pass --insecure to skip verification (testing only), or fix the certificate/trust store first."
  elif [ "$reach_rc" -ne 0 ]; then
    echo "Warning: '${url}' was not reachable just now. Configuring it anyway - CrowdSec will simply fail to deliver notifications until it is reachable."
  else
    echo "Reachable."
  fi

  local skip_tls="false"
  [ "$insecure" = "yes" ] && skip_tls="true"

  local profiles_changed="no"
  enable_profile_notification && profiles_changed="yes"

  local headers_block=""
  local h
  for h in "${headers[@]}"; do
    headers_block="${headers_block}  ${h}
"
  done

  mkdir -p "$(dirname "$HTTP_NOTIF_FILE")" || return 1

  local tmp
  tmp=$(mktemp) || return 1

  generate_http_notification "$headers_block" | sed \
    -e "s#__OTLP_URL__#${url}#" \
    -e "s#__OTLP_SKIP_TLS__#${skip_tls}#" \
    > "$tmp"

  local backup=""
  local existed="no"
  local http_changed="yes"

  if [ -e "$HTTP_NOTIF_FILE" ]; then
    if cmp -s "$tmp" "$HTTP_NOTIF_FILE"; then
      echo
      echo "[$HTTP_NOTIF_FILE] unchanged"
      rm -f "$tmp"
      http_changed="no"
    fi

    if [ "$http_changed" = "yes" ]; then
      backup=$(mktemp)
      cp -a "$HTTP_NOTIF_FILE" "$backup"
      existed="yes"
    fi
  fi

  if [ "$http_changed" = "yes" ]; then
    cp "$tmp" "$HTTP_NOTIF_FILE" || {
      rm -f "$tmp" "$backup"
      return 1
    }
  fi
  rm -f "$tmp"

  if [ "$http_changed" = "no" ] && [ "$profiles_changed" = "no" ]; then
    return 0
  fi

  echo
  [ "$http_changed" = "yes" ] && echo "[$HTTP_NOTIF_FILE] updated"

  if ! container_running; then
    echo
    echo "Hub is not running - this will take effect on the next '$0 up'."
    rm -f "$backup"
    return 0
  fi

  # Notification plugin configs are only read at CrowdSec startup, not
  # hot-reloaded - confirmed live 2026-08-22 (a template fix silently kept
  # rendering the old output until the container was restarted). Same
  # applies to profiles.yaml's notification wiring, so any change to
  # either file needs this same restart.
  echo
  echo "Restarting crdsec-hub to apply (config is only read at startup) ..."

  if ! compose restart crowdsec; then
    log_err "Restart failed. Restoring previous configuration."
    if [ "$http_changed" = "yes" ]; then
      if [ "$existed" = "yes" ]; then
        cp -a "$backup" "$HTTP_NOTIF_FILE"
      else
        rm -f "$HTTP_NOTIF_FILE"
      fi
    fi
    if [ "$profiles_changed" = "yes" ]; then
      cp -a "$(dirname "$0")/config/profiles.yaml.bak" "$(dirname "$0")/config/profiles.yaml"
    fi
    rm -f "$backup"
    return 1
  fi

  rm -f "$backup"

  echo
  echo "OTLP endpoint configured: ${url}"
  [ "$profiles_changed" = "yes" ] && echo "profiles.yaml: http_default enabled for default_ip_remediation (was commented out)."
  echo "Run '$0 testnotif' to send a test alert and verify delivery (this reaches the real endpoint - not run automatically here to avoid pushing a dummy record on every reconfigure)."
}


test_notification()
{
  local name="${1:-http_default}"

  require_running_container || return 1
  dexec cscli notifications test "$name"
}


###############################################################################
# Help / version
###############################################################################

show_version()
{
  echo "crdsec-hub $CRDSEC_HUB_VERSION"
}


show_help()
{
  echo
  echo "crdsec-hub - central CrowdSec hub"
  echo "--------------------------------------"
  echo
  echo "Syntax: crdsec-hub.sh [command]"
  echo
  printf "  %-24s%s\n" "-" "Show status"
  printf "  %-24s%s\n" "help" "Show this help"
  printf "  %-24s%s\n" "up" "Start the hub container (docker compose up -d)"
  printf "  %-24s%s\n" "down" "Stop the hub container (keeps data/config volumes)"
  printf "  %-24s%s\n" "shell" "Open a shell inside the running container"
  printf "  %-24s%s\n" "status" "Show hub status"
  printf "  %-24s%s\n" "alerts" "List CrowdSec alerts"
  printf "  %-24s%s\n" "decisions" "List active CrowdSec decisions"
  printf "  %-24s%s\n" "metrics" "Show hub CrowdSec metrics"
  printf "  %-24s%s\n" "log [lines]" "Show container log (default: 100 lines)"
  printf "  %-24s%s\n" "logs" "Show the full container log, no line limit"
  printf "  %-24s%s\n" "ban <IP> [duration]" "Add a CrowdSec decision (hub-wide, all agents pick it up)"
  printf "  %-24s%s\n" "unban <IP>" "Delete CrowdSec decisions for an IP"
  printf "  %-24s%s\n" "register <name> [-f]" "Register both machine + bouncer, print a ready-to-paste 'crdsectl register' line"
  printf "  %-24s%s\n" "addmachine <name> [-f]" "Register just a remote agent machine, print its credentials"
  printf "  %-24s%s\n" "machines" "List registered machines"
  printf "  %-24s%s\n" "addbouncer <name> [-f]" "Register just a remote bouncer, print its API key"
  printf "  %-24s%s\n" "bouncers" "List registered bouncers"
  printf "  %-24s%s\n" "otlp <url> [opts]" "Configure and apply the OTLP notification endpoint"
  printf "  %-24s%s\n" "testnotif [name]" "Send a test alert through a notification plugin (default: http_default)"
  printf "  %-24s%s\n" "duration [value]" "Show or set the default ban duration (e.g. 4h)"
  printf "  %-24s%s\n" "progressive [on|off]" "Show or set progressive (escalating) ban duration"
  printf "  %-24s%s\n" "profile" "Open profiles.yaml in \$EDITOR (or vi) and restart"
  printf "  %-24s%s\n" "version" "Show version information"
  echo
}


###############################################################################
# Main
###############################################################################

main()
{
  case "$1" in
    "")
      show_status
      ;;

    help|-h|--help)
      show_help
      ;;

    up)
      bring_up
      ;;

    down)
      bring_down
      ;;

    shell)
      open_shell
      ;;

    status)
      show_status
      ;;

    alerts)
      list_alerts
      ;;

    decisions)
      list_decisions
      ;;

    metrics)
      show_metrics
      ;;

    log)
      show_log "$2"
      ;;

    logs)
      show_full_log
      ;;

    ban)
      ban_ip "$2" "$3"
      ;;

    unban)
      unban_ip "$2"
      ;;

    register)
      shift
      register_machine "$@"
      ;;

    addmachine)
      shift
      add_machine "$@"
      ;;

    machines)
      list_machines
      ;;

    addbouncer)
      shift
      add_bouncer "$@"
      ;;

    bouncers)
      list_bouncers
      ;;

    otlp)
      shift
      configure_otlp "$@"
      ;;

    testnotif)
      test_notification "$2"
      ;;

    duration)
      show_or_set_duration "$2"
      ;;

    progressive)
      show_or_set_progressive "$2"
      ;;

    profile)
      edit_profiles
      ;;

    version|-v|--version)
      show_version
      ;;

    *)
      log_err "Unknown option: '$1'"
      show_help
      return 1
      ;;
  esac
}


main "$@"
