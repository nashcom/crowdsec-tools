#!/bin/bash

# Standalone isolation test: POSTs a minimal, spec-compliant OTLP JSON logs
# export (real resourceLogs/scopeLogs/logRecords envelope, typed AnyValue
# attribute values) directly to an OTLP/HTTP endpoint via curl - no
# CrowdSec/crdsec-hub involved at all. Used to confirm/deny whether a
# receiving endpoint (e.g. Loki's /otlp/v1/logs) actually requires the full
# OTLP envelope, independent of anything this project's Go template does.
#
# Usage: ./testing/test-otlp.sh <url> [bearer-token]

URL="$1"
TOKEN="$2"

if [ -z "$URL" ]; then
  echo "Usage: $0 <url> [bearer-token]" >&2
  exit 1
fi

NOW_NS=$(date +%s%N)

BODY=$(cat <<EOF
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "crdsectl" } }
        ]
      },
      "scopeLogs": [
        {
          "scope": {},
          "logRecords": [
            {
              "timeUnixNano": "${NOW_NS}",
              "observedTimeUnixNano": "${NOW_NS}",
              "severityNumber": 9,
              "severityText": "INFO",
              "body": { "stringValue": "test-otlp.sh isolation test" },
              "attributes": [
                { "key": "crowdsec.decision.type", "value": { "stringValue": "ban" } },
                { "key": "crowdsec.source.ip", "value": { "stringValue": "10.10.10.10" } }
              ]
            }
          ]
        }
      ]
    }
  ]
}
EOF
)

curl_args=(--silent --show-error -o - -w '\nHTTP %{http_code}\n' -H "Content-Type: application/json")
[ -n "$TOKEN" ] && curl_args+=(-H "Authorization: Bearer ${TOKEN}")

curl "${curl_args[@]}" -X POST "$URL" -d "$BODY"
