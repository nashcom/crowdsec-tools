# crdsectl - CrowdSec-based auth-failure protection

CrowdSec-based brute-force / auth-failure protection for service logs, replacing a fail2ban-style setup: acquire a
log, parse an auth failure out of it, score it with a CrowdSec scenario, enforce with a bouncer.

The pattern isn't tied to any one service. HCL Domino (Internet password authentication failures, via its output log) 
is the first one implemented, because that's the immediate need - additional services (SSH and others)
are expected to follow the same acquisition/parser/scenario shape as they're added.

## Architecture

```text
              crdsec-hub (optional)
              CrowdSec central LAPI
                      |
           +----------+----------+
           |                     |
        alerts                decisions
           ^                     |
           |                     v
     crdsectl agents          bouncers
    (CrowdSec engines)           |
           ^                     v
      service logs            nftables
```

`crdsectl` (the agent) owns all the service-specific knowledge - acquisition, parser, scenario. `crdsec-hub` is
generic: it just aggregates alerts and distributes decisions, a plain CrowdSec LAPI role with no awareness of
Domino, SSH, or any other service. It's optional - each `crdsectl` agent runs fully standalone by default, with
its own local decision database, and only reports to a shared hub if explicitly `register`ed against one.

## Hub registration

Connecting a `crdsectl` agent to a self-hosted `crdsec-hub` needs two separate credentials, because `crowdsec` and
`crowdsec-firewall-bouncer` are two separate processes on the agent, each authenticating for a different one-way
operation. `crdsec-hub.sh register <name>` issues both in one call (shown below as its two underlying steps -
`addmachine`/`addbouncer` also exist standalone for issuing just one):

```text
crdsec-hub
     |
     +-- addmachine domino01
     |       |
     |       +-- login + password
     |              |
     |              v
     |       crdsectl register ...
     |       local_api_credentials.yaml
     |
     +-- addbouncer domino01
             |
             +-- API key
                    |
                    v
             crowdsec-firewall-bouncer.yaml
```

- **User/password registration** (`addmachine`) - a login + password pair, used by the agent's own `crowdsec`
  process to submit alerts it detects locally. Write-only: lets that server report in, nothing more.
- **Key registration** (`addbouncer`) - a single API key, used by the agent's own `crowdsec-firewall-bouncer`
  process to poll the current decision list and enforce it via nftables. Read-only: lets that server enforce bans,
  nothing more.

Keeping them separate limits blast radius if one leaks: the bouncer key alone can't be used to submit fake alerts,
and the machine password alone can't be used to just read the ban list.

Example, end to end - `crdsec-hub.sh register` issues both credentials in one call and prints the exact
`crdsectl register` line built from them, ready to paste onto the agent:

```bash
# On the hub:
./crdsec-hub.sh register domino01
# ...
# Run this on the agent:
#   crdsectl trust <hub-ca-cert-path>   # only if this hub uses a self-signed CA
#   crdsectl register https://hub.example.com:8443 domino01 domino01-pw domino01-bouncer-key

# On the agent (domino01):
crdsectl trust hub-ca.crt                                             # only if the hub uses a self-signed CA
crdsectl register https://hub.example.com:8443 domino01 domino01-pw domino01-bouncer-key
```

### How `register` builds that line

`register <name>` (function `register_machine()` in `crdsec-hub.sh`) is a thin wrapper around the two steps
above - it doesn't talk to `cscli` any differently, it just captures what they print, pulls the two secrets out
of it, and hands back one command instead of two credential blobs to copy by hand:

```text
register domino01
     |
     +-- cscli machines add domino01 --auto -f - --url <hub-url>   (captured, stdout+stderr)
     |         |
     |         +-- parse the "password:" line
     |
     +-- cscli bouncers add domino01                                (captured, stdout+stderr)
     |         |
     |         +-- parse the indented key line
     |
     +-- print:
           crdsectl trust <hub-ca-cert-path>
           crdsectl register <hub-url> domino01 <password> <bouncer-key>
```

Both calls are captured with `2>&1`, not just stdout - found the hard way, live (2026-08-22): `cscli machines
add ... -f -` writes its output (the confirmation line *and* the url/login/password block) to **stderr**, while
`cscli bouncers add` writes its key to **stdout** - an inconsistency between the two `cscli` subcommands
themselves, not a bug in the capture approach. First diagnosed via a raw-bytes (`cat -A`) dump of what actually
got captured, rather than guessing - it showed the machine credentials captured as completely empty despite
printing correctly to the terminal (stderr passing straight through, uncaptured, while a stdout-only `$(...)`
got nothing). If parsing ever fails again despite the `2>&1` fix, `register` falls back to printing that same
raw-bytes dump and the credentials from the (still-printed) `cscli` output above it, so you can copy them
manually into the `crdsectl register <hub-url> <name> <password> <bouncer-key>` template it prints instead.

`addmachine`/`addbouncer` still exist separately for issuing just one credential (e.g. rotating a leaked bouncer
key without touching the machine registration).

## Domino-specific configuration

What `crdsectl` currently generates and manages for Domino - the first service implemented (see Architecture above).
Generated by `crdsectl install`/`update` into the paths shown, regenerated (never hand-edited) each time; kept in
sync here manually with `crdsectl.sh`'s `generate_acquisition`/`generate_parser`/`generate_scenario` functions, which
remain the source of truth if this drifts.

`/etc/crowdsec/acquis.d/domino.yaml` - watches `$DOMINO_OUTPUT_LOG` (defaults to `$DOMINO_DATA_PATH/notes.log`,
`DOMINO_DATA_PATH` defaults to `/local/notesdata`; all three env vars can be pre-exported to override, e.g. for
container-based Domino deployments - `DOMINO_OUTPUT_LOG` is the same env var name the Domino start script itself
uses, so an existing deployment's own config is picked up automatically):

```yaml
filenames:
  - ${DOMINO_OUTPUT_LOG}

labels:
  type: domino
```

`/etc/crowdsec/parsers/s01-parse/domino-auth.yaml` - matches one specific Domino output log failure wording
(`authentication failure using internet password`) and extracts the source IP. Other Domino auth-failure types
aren't matched by this parser:

```yaml
name: domino-auth
description: "Parse HCL Domino authentication failures"

filter: "evt.Line.Labels.type == 'domino'"

grok:
  pattern: '.*\[%{IP:source_ip}\] authentication failure using internet password.*'
  apply_on: Line.Raw

statics:
  - meta: service
    value: domino
  - meta: log_type
    value: domino_failed_auth
  - meta: source_ip
    expression: evt.Parsed.source_ip
```

`/etc/crowdsec/scenarios/domino-auth-bf.yaml` - a leaky bucket grouped by source IP. Confirmed empirically (via
`crdsectl logtest`) to trigger a ban on the 6th failed attempt from the same IP within the window - `capacity: 5`
overflows on the *next* event past capacity, not at capacity itself - with a 5-minute `blackhole` to prevent
immediate re-triggering once the ban expires:

```yaml
type: leaky
name: domino-auth-bf
description: "Detect HCL Domino authentication brute force attempts"

filter: "evt.Meta.log_type == 'domino_failed_auth'"
groupby: evt.Meta.source_ip

capacity: 5
leakspeed: "5m"
blackhole: 5m
```

## Layout

```
crdsectl/       crdsectl.sh - the actual deliverable, installed on each
                protected server. See crdsectl/README.md.
crdsec-hub/     crdsec-hub.sh - a separate, self-hosted central CrowdSec
                hub multiple crdsectl agents can report to.
                See crdsec-hub/README.md.
```

`crdsectl.sh` and `crdsec-hub.sh` are two different, independent tools - one protects a single server, the
other is an optional central point for a fleet of them. Neither depends on the other being installed.

Run `crdsectl.sh help` (or `crdsec-hub.sh help`) for command reference - that's the authoritative source, not duplicated here.
