# config/

Bind-mounted onto the container's `/etc/crowdsec` (see `../docker-compose.yml`). Not committed (see
`../.gitignore` - this file is the one deliberate exception) - this is real runtime state, including credentials.

Created and populated automatically by CrowdSec itself on `../crdsec-hub.sh up`, plus whatever `register`/
`addmachine`/`addbouncer`/`otlp` write into it afterward. Notably includes:

- `local_api_credentials.yaml` / `online_api_credentials.yaml` - real credentials, never share these.
- `notifications/http.yaml` - the OTLP export config `../crdsec-hub.sh otlp` manages (see the root README's
  "OpenTelemetry event export" section) - may contain a real bearer token if `--token`/`--header` was used.
- `parsers/`, `scenarios/`, `collections/`, `postoverflows/` - mostly symlinks into `hub/`, CrowdSec's own Hub
  content system. Regenerated automatically on `up`; don't hand-edit or expect them to survive a fresh checkout.
- `profiles.yaml` - which notifications fire for which decisions; already has `http_default` enabled by default.

Nothing here is meant to be hand-edited directly except via the `crdsec-hub.sh` commands that manage it.
