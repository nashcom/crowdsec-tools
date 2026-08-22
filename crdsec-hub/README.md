# crdsec-hub.sh

Brings up and operates a self-hosted central CrowdSec HUB - a single CrowdSec instance holding the LAPI and decision
database that multiple crdsectl (../crdsectl) agents can report to and query decisions from, instead of each one
running fully standalone.

This is NOT the CrowdSec Console (app.crowdsec.net). That is a hosted SaaS product with no self-hosted equivalent -
`crdsectl.sh enroll <token>` already covers connecting to it, and that's unrelated to this tool. This is a different,
self-hosted concept that happens to serve a similar "one place to see everything" purpose.

See the [root README](../README.md#architecture) for the overall architecture diagram. In short: crdsec-hub
itself has no Domino-specific (or any service-specific) knowledge at all - the CrowdSec engines running on each
protected server (`../crdsectl`) own all of that (acquisition, parser, scenario). This tool only aggregates alerts
and distributes decisions, a generic CrowdSec LAPI role.

## Status

Live-tested end to end (2026-08-21): brought up via real `docker compose`, `addmachine`/`addbouncer` produced real
working credentials, a `../crdsectl` agent registered against it (`crdsectl register`) and reported a real decision,
and that decision showed up here via `alerts`/`decisions`. Cert generation (`gen-cert.sh`) separately verified
(chain validates, correct SAN, ECDSA key confirmed).

Not yet tested: a real remote agent (different physical/VM host, not a co-located test container) reporting over a
real network path, or a production-issued (non-self-signed) certificate.

## Files

- `docker-compose.yml` - the actual deployment: CrowdSec's own official `crowdsecurity/crowdsec` image (no custom
  build needed - it runs crowdsec directly as PID 1, unlike ../crdsectl's agent test image, which deliberately
  mirrors a real package-manager install and needs systemd for that), plus nginx in front of it for TLS. crowdsec
  itself publishes no port directly anymore - nginx is the sole entry point. Both services join `crowdsec-net`,
  which compose creates/owns itself (a fixed name, not the default project-prefixed one) - shared with
  ../crdsectl/run-install-test-container.sh's agent test container when that's run with `NETWORK_MODE=bridge` instead of its default
  `--network host`.
- `crdsec-hub.sh` - runs on the host, not inside the container. `up`/`down` delegate to `docker compose`;
  `status` and the machine/bouncer commands use `docker exec` against the running container.
- `env.example` - copy to `.env` to override `HUB_HOST` (the hostname/IP remote agents use to reach this hub -
  defaults to `localhost`, only useful for same-machine testing), `NGINX_HTTPS_PORT`, `COLLECTIONS`, or
  `IMAGE_TAG`. Not required; the compose file's own defaults apply without one.
- `data/` and `config/` - created on first `up`, bind-mounted host directories (not Docker-managed volumes) holding
  the decision database and CrowdSec's config, including whatever `addmachine`/`addbouncer` generate. Deliberately
  plain host directories rather than opaque Docker volumes, so the state is easy to find, inspect, or back up
  directly. Gitignored - this is runtime state, not something to commit.
- `nginx.conf` - TLS termination in front of the LAPI. HTTPS-only by design - nginx listens on host port 8443 only
  (no port 80, nothing to redirect), reverse-proxying to the `crowdsec` compose service over plain HTTP internally -
  crowdsec itself is not reachable from the host directly.
- `gen-cert.sh` - generates a local test CA (`tls/ca.key` + `tls/ca.crt`, ECDSA P-256) and a leaf cert signed
  by it (`tls/tls.key` + `tls/tls.crt`, also ECDSA P-256) for local testing, all in `tls/`. The CA is only generated
  once and reused on every later run - regenerating it would invalidate every agent that already trusts the old
  `ca.crt`. The leaf (key and cert both) is always regenerated fresh each run, since only this hub itself needs to
  trust it. Validity periods are configurable via `.env`'s `CA_DAYS`/`LEAF_DAYS` (defaults 3650/365). Note that
  means the CA private key (`ca.key`) ends up inside the directory bind-mounted into the nginx container -
  acceptable for local testing, but a production CA key should not be handled this way. Distribute `tls/ca.crt`
  (never `ca.key`) to remote crdsectl agents' trust stores so they can validate this hub's leaf cert. Not for
  production otherwise either - a real deployment wants a real CA-issued cert instead (e.g. via ACME, see
  nashcom-labs/lego). `tls/` is gitignored.
- `testing/` - dev/debug tooling, not part of normal operation:
  - `test-otlp.sh` - standalone isolation test: POSTs a minimal, hand-built, spec-compliant OTLP JSON logs export
    directly to an OTLP/HTTP endpoint via `curl`, with no CrowdSec/`crdsec-hub` involved at all. Used to confirm
    whether a receiving endpoint requires the real OTLP envelope, independent of this project's own Go template -
    see the "OpenTelemetry event export" section below for how it was used to isolate a real bug.

## Usage

```bash
cp env.example .env       # optional, only if you want non-default settings
./gen-cert.sh        # populates tls/ - required before "up"
./crdsec-hub.sh up
./crdsec-hub.sh register <name>   # register a remote crdsectl agent (machine + bouncer)
./crdsec-hub.sh status
```

## Commands

Kept in sync with `crdsec-hub.sh help` - run that directly if this drifts.

| Command                       | Description                                                                                                                                 |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| *(none)*                      | Show status                                                                                                                                 |
| `help`                        | Show this help                                                                                                                              |
| `up`                          | Start the hub container (docker compose up -d)                                                                                              |
| `down`                        | Stop the hub container (keeps data/config volumes)                                                                                          |
| `shell`                       | Open a shell inside the running container                                                                                                   |
| `status`                      | Show hub status                                                                                                                             |
| `alerts`                      | List CrowdSec alerts                                                                                                                        |
| `decisions`                   | List active CrowdSec decisions                                                                                                              |
| `metrics`                     | Show hub CrowdSec metrics                                                                                                                   |
| `ban <IP> [duration]`         | Add a CrowdSec decision (hub-wide, all agents pick it up)                                                                                   |
| `unban <IP>`                  | Delete CrowdSec decisions for an IP                                                                                                         |
| `register <name> [--force]`   | Register both machine + bouncer, print a ready-to-paste "crdsectl register" line - `--force` clears any existing entry with that name first |
| `addmachine <name> [--force]` | Register just a remote agent machine, print its credentials                                                                                 |
| `machines`                    | List registered machines                                                                                                                    |
| `addbouncer <name> [--force]` | Register just a remote bouncer, print its API key                                                                                           |
| `bouncers`                    | List registered bouncers                                                                                                                    |
| `otlp <url> [--insecure]`     | Configure and apply the OTLP notification endpoint                                                                                          |
| `testnotif [name]`            | Send a test alert through a notification plugin (default: `http_default`)                                                                   |
| `version`                     | Show version information                                                                                                                    |

See the [root README](../README.md#hub-registration) for the registration flow diagram and an end-to-end example -
`addmachine` (user/password registration) and `addbouncer` (key registration) serve different purposes, explained
there. `register` runs both in one call and prints a ready-to-paste `crdsectl register ...` line built from the
actual credentials just issued - the normal path for registering a new agent. `addmachine`/`addbouncer` stay
available separately for re-issuing just one credential (e.g. rotating a leaked bouncer key) without touching the
other. Either way, what gets printed goes into the corresponding agent's `../crdsectl/crdsectl.sh register` call
(or directly into `local_api_credentials.yaml` / the bouncer config), pointed at this hub's HTTPS port (8443 by
default). That agent also needs `tls/ca.crt` (or your real CA's cert, in production) in its trust store
(`crdsectl.sh trust <ca-cert-path>`) to validate this hub's leaf cert.

`ban`/`unban` add or remove a decision directly on the hub, independent of any single agent - every agent registered
against this hub picks it up on its bouncer's next poll. Same underlying mechanism as `../crdsectl`'s own
`crdsectl.sh block`/`unblock`, just centralized.

`metrics` shows the hub *container's own* CrowdSec metrics (LAPI activity: machines/bouncers, alerts received,
decisions issued) - not each agent's parser/bucket metrics, since parsing happens on the agent that owns the log
source, not here. For an agent's own local metrics, run `crdsectl metrics` on that agent - it queries its own local
Prometheus endpoint regardless of whether it's registered against this hub or running standalone.

## OpenTelemetry event export (OTLP)

`config/notifications/http.yaml`'s `format:` template wraps each CrowdSec decision alert in a real, minimal OTLP/HTTP
envelope (`resourceLogs[].scopeLogs[].logRecords[]`) and embeds the CrowdSec-specific content as a flat JSON string
inside `logRecords[0].body.stringValue` - matching the convention already used elsewhere for Domino event logs
(snake_case fields, a flat `resource` object, a flat `attributes` object with dotted-namespace keys), unchanged in
shape, just nested one level deeper as text rather than sent as the raw HTTP body. This matches the actual wire
pattern used by the reference Domino->OTLP pipeline (`domfwd`, a separate C-API servertask) - confirmed by reading
its source: it builds the same flat JSON, then embeds it as a single JSON string inside a minimal envelope whose
own `resource.attributes` only carries `service.name`, not a full field-by-field OTLP attribute mapping.

A flat body with **no** envelope at all was tried first and confirmed live (2026-08-22) to be rejected by Loki's
real OTLP receiver - it fails Content-Type sniffing first (Loki rejects any request with no recognized
Content-Type before even parsing the body), and once that's fixed, fails again with `at least one valid stream is
required for ingestion` (Loki looks for `resourceLogs` and finds none - a flat body has none). A hand-built minimal
envelope posted directly via `curl`, bypassing CrowdSec entirely (`./testing/test-otlp.sh <url> [token]`), confirmed the
receiver accepts a real envelope (`204`) - see that script for a from-scratch example of the required shape.

Configure and apply the target endpoint with:

```bash
./crdsec-hub.sh otlp <url> [--insecure] [--token <token>] [--header "Name: Value"]...
```

This regenerates `config/notifications/http.yaml` from the template above, checks the endpoint is reachable
(reporting a clear message if the TLS certificate specifically doesn't validate, same style as `crdsectl.sh
register`'s pre-flight check - non-fatal here, since an unreachable endpoint just means notifications won't
deliver yet), installs the file (no-op if unchanged), and restarts the hub (notification plugin config is only
read at CrowdSec startup, confirmed live - a template change silently kept using the old version until restarted).
It does **not** send a test alert automatically - that would push a dummy record to the real endpoint on every
reconfigure. Run `./crdsec-hub.sh testnotif [name]` (default `http_default`) afterward, any time, to verify
delivery through the real endpoint without regenerating config.

- `--insecure` sets `skip_tls_verification: true`, for a self-signed/testing endpoint - omit it for a real
  endpoint with a trusted certificate.
- `--token <token>` sets `Authorization: Bearer <token>` - the common case for an authenticated OTLP/Loki
  receiver.
- `--header "Name: Value"` sets any other header verbatim, repeatable - e.g. multi-tenant Loki's
  `X-Scope-OrgID`. Combine with `--token` freely; both feed the same `headers:` block.
- `Content-Type: application/json` is always set, unconditionally - not something `--header` needs to supply.
  The body is always JSON (this template only ever emits JSON), but the CrowdSec `http` plugin does not set
  Content-Type on its own. Loki's OTLP receiver (and OTLP/HTTP receivers generally) reject a request with no
  recognized Content-Type before even looking at the body - confirmed live (2026-08-22): `content type:  is not
  supported` (note the empty value) from Loki, fixed by adding this header.

Since `log_level: debug` logs the actual outgoing request, any configured header value (including a bearer
token) is visible via `./crdsec-hub.sh log` while debugging - keep that in mind before sharing log output.

**Status: live-verified end to end (2026-08-22)** against a real Loki instance, with both a synthetic
`cscli notifications test` alert (clean `204`) and a genuine `crdsectl`-detected decision (visible and correctly
parsed/leveled in Grafana), across multiple independent production machines reporting to the same hub. Point `otlp`
at a real OTLP/Loki endpoint directly; `http.yaml`'s `log_level: debug` (visible via `crdsec-hub.sh log`) is enough
on its own to inspect the exact outgoing request during setup - no separate local debug receiver needed.

**Outer OTLP envelope** (real, spec-compliant - `logRecords[0]` only):

| Envelope field                          | Source                                                          |
|------------------------------------------|-------------------------------------------------------------------|
| `resourceLogs[0].resource.attributes`     | *(fixed)* `service.name: "crowdsec"` - routing only, nothing else |
| `resourceLogs[0].scopeLogs[0].scope.name` | *(fixed)* `"crdsec-hub"`                                         |
| `logRecords[0].timeUnixNano`              | `Alert.StartAt`                                                 |
| `logRecords[0].observedTimeUnixNano`      | *(webhook build time)*                                          |
| `logRecords[0].severityNumber/Text`       | `Alert.Simulated` / `Decisions[0].Origin` (see severity mapping below) |
| `logRecords[0].body.stringValue`          | the flat inner JSON below, double-JSON-encoded                  |

**Inner JSON** (the `body.stringValue` content - same flat, dotted-key shape used for Domino event logs elsewhere,
unchanged from the original design, just relocated):

| CrowdSec field                                                  | Inner JSON field                     |
|-------------------------------------------------------------------|-----------------------------------|
| `Alert.StartAt`                                                 | `time_unix_nano`                     |
| *(webhook build time)*                                          | `observed_time_unix_nano`            |
| `Alert.Simulated` / `Decisions[0].Origin`                       | `severity_number`/`severity_text`    |
| `Alert.Message`                                                 | `body`                               |
| *(fixed)*                                                       | `scope.name: "crowdsec.decision"`    |
| *(fixed)*                                                       | `resource."service.name": "crowdsec"`|
| `Alert.MachineID`                                               | `resource."service.instance.id"`     |
| *(the hub's own hostname - see caveat below)*                   | `resource."host.name"`               |
| `Decisions[0].{Type,Duration,Scenario,Origin,Value,UUID}`       | `attributes."crowdsec.decision.*"`   |
| `Alert.UUID`                                                    | `attributes."crowdsec.alert.uuid"`   |
| `GetMeta(alert, "service")[0]`                                  | `attributes."crowdsec.service"`      |
| `Alert.Remediation`                                             | `attributes."crowdsec.remediation"`  |
| `Alert.Simulated`                                               | `attributes."crowdsec.simulated"`    |
| `Alert.Source.{IP,Scope,Cn,AsNumber,AsName,Latitude,Longitude}` | `attributes."crowdsec.source.*"`     |
| `Alert.EventsCount`                                             | `attributes."crowdsec.events_count"` |

**Severity mapping:** `WARN` (13) for a genuine automated detection that actually got enforced (a security control
correctly blocking an attacker is CrowdSec working as designed, not a malfunction). Downgraded to `INFO` (9) for a
simulated (dry-run) decision or a manually `cscli`-originated one (an admin action, not a detected threat) -
`Alert.Simulated == true` or `Decisions[0].Origin != "crowdsec"`. Not yet differentiating ban vs. captcha decision
types, since `profiles.yaml` only ever configures `ban` here.

Known caveats:

- **`Alert.Simulated`/`Decisions[0].Origin` are Go pointer types (`*bool`/`*string`)** - confirmed live via temporary
  debug fields (2026-08-22). Comparing them with `printf "%s"`/`"%v"` does **not** dereference the pointer the way
  it might look like it should: `%v` on a pointer-to-scalar (not struct/slice/map) prints the hex address, and `%s`
  on a `*string` fails outright since `*string` isn't a `Stringer` - both produced a value that never matched the
  literal being compared against, so an earlier version of this template's severity downgrade fired unconditionally.
  Fixed by reusing `toJson` for the comparison instead (`eq ($alert.Simulated | toJson) "true"`,
  `ne ($decision.Origin | toJson) "\"crowdsec\""`) - `toJson` goes through `encoding/json.Marshal`, which does
  follow pointers, and the same mechanism is relied on again for the pointer fields placed raw into the inner
  `dict` (`encoding/json.Marshal` dereferences pointers anywhere in a value tree, not just at the top level) -
  confirmed working live end to end (2026-08-22): a clean `204` from Loki with `crowdsec.decision.origin`
  correctly rendered (`"cscli"` for the `cscli notifications test` alert), no double-encoding artifacts.
  **Lesson: don't use `printf` to "coerce" a suspected pointer field in this template - use `toJson` instead.**
- **Single-decision assumption** - uses `index .Decisions 0`. Every payload observed so far has had exactly one
  decision per alert, but this would need to become a `range` loop if that ever stops holding (e.g. a Range-scope
  or multi-decision scenario).
- **`host.name` (inner JSON) is always the hub's own hostname**, not the reporting agent's - the `Hostname` template
  function reflects wherever the template itself executes (the hub), not where the alert originated. The per-agent
  identity lives in `resource."service.instance.id"` (the `machine_id`) instead, which does vary correctly per agent.
- **`crowdsec.service`** (via `GetMeta`) - confirmed live (2026-08-22) that `GetMeta(alert, "service")` returns an
  empty slice for `cscli notifications test`'s synthetic alert (not just a hypothetical future scenario without a
  `service` meta key), and `index ... 0` on an empty slice panics the whole plugin. Guarded with a length check;
  `crowdsec.service` falls back to `""` when the meta key is absent.
- **Each JSON object is already a complete, self-contained OTLP export request** - "one alert, one HTTP POST, one
  export request" is the natural OTLP/HTTP shape, unlike the old flat design's array-wrapping concern (that one
  relied on `group_wait`/`group_threshold` staying unconfigured to avoid needing an array wrapper around multiple
  bare JSON objects). A real OTLP envelope has no such issue - each request is already self-describing.
- Template functions available: Sprig, plus CrowdSec's own `Hostname`, `GetMeta(alert, key)`, `HTMLEscape`,
  `CrowdsecCTI`. Confirmed via a live error rather than docs alone - an earlier search result gave the wrong name
  (`GetHostname`, which doesn't exist; the correct one is `Hostname`), caught via `crdsec-hub.sh log`.

## Network exposure

Prefer keeping this hub on a private network reachable only by the `crdsectl` agents that need it - a VPN, a
private WAN between sites, or firewall/security-group rules restricting the HTTPS port (8443) to known agent
source IPs. There's no upside to exposing it publicly when private connectivity already exists between the hub
and its agents.

If agents are genuinely distributed with no existing private link, public exposure is a supported configuration -
CrowdSec's own multi-server-setup docs explicitly describe running a LAPI reachable over the internet, with the
caveat to enable SSL if exposed that way, which this hub already does (nginx TLS termination; no HTTP port is
published at all, see `docker-compose.yml`). The registration credentials are also high-entropy - `addmachine`
(`cscli machines add --auto`) generates a long random login/password, and the bouncer key is similarly random -
so credential-guessing isn't a realistic risk here.

What TLS and authentication do *not* protect against: they secure data (only valid credentials can submit alerts
or read decisions), not the network-level attack surface itself - an exposed endpoint still has to accept
connections and handle requests before authentication even runs. If public exposure is unavoidable, add IP
allowlisting at the firewall or nginx level for known agent source IPs as defense-in-depth on top of, not instead
of, what's already here.

### Networking for local testing

If you're running both an agent test container (`../crdsectl/run-install-test-container.sh`) and this hub on the same Docker host,
`localhost` inside the agent container does not reach the host - they're separate network namespaces by default.
Either run the agent with `NETWORK_MODE=host` (shares the real host netns, default in `../crdsectl/run-install-test-container.sh`) or
`NETWORK_MODE=bridge` (joins the `crowdsec-net` network this hub's `docker-compose.yml` also creates, reaching the
hub by container name instead of `localhost`). A real Domino server is never on this hub's Docker network, so it
always reaches the hub by its actual `HUB_HOST`/port over the network - this only matters for local test topology.
