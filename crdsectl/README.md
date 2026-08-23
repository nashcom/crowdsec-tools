# crdsectl.sh

Installs, configures and operates CrowdSec as a per-service fail2ban replacement, on a single protected server.
Domino (Internet password authentication failures) is the service implemented today.

## Commands

Kept in sync with `crdsectl.sh help` - run that directly if this drifts.

| Command                                       | Description                                                            |
|-----------------------------------------------|------------------------------------------------------------------------|
| *(none)*                                      | Show CrowdSec status                                                   |
| `help`                                        | Show this help                                                         |
| `install [log-file] [token]`                  | Install CrowdSec, bouncer, service config, optional console enroll     |
| `update [log-file]`                           | Update embedded CrowdSec configuration                                 |
| `test`                                        | Test configuration and parser                                          |
| `status`                                      | Show CrowdSec status                                                   |
| `alerts`                                      | List CrowdSec alerts                                                   |
| `decisions`                                   | List active CrowdSec decisions                                         |
| `metrics`                                     | Show CrowdSec metrics                                                  |
| `collections`                                 | List installed CrowdSec collections                                    |
| `enroll <token>`                              | Enroll this instance with the CrowdSec console (SaaS)                  |
| `trust <ca-cert-path>`                        | Trust a self-hosted hub's CA (run before `register`, if needed)        |
| `register <url> <login> <pw> <key>`           | Report to / consume decisions from a self-hosted hub (`--force` overwrites) |
| `block <IP> [duration]`                       | Add a CrowdSec decision                                                |
| `unblock <IP>`                                | Delete CrowdSec decisions for an IP                                    |
| `blocktest [IP] [duration]`                   | Block a test IP and verify nftables (default 1.2.3.4, 10m)             |
| `logtest [IP]`                                | Write real test log lines and verify the full log->decision pipeline   |
| `firewall`                                    | Show CrowdSec nftables rules                                           |
| `log [lines]`                                 | Show CrowdSec journal (default: 100 lines)                             |
| `reload`                                      | Validate and reload CrowdSec                                           |
| `restart`                                     | Validate and restart CrowdSec and bouncer                              |
| `systemd [cmd]`                               | Manage CrowdSec and bouncer services                                   |
| `config`                                      | Show CrowdSec configuration                                            |
| `version`                                     | Show version information                                               |

## Quick start

On a Domino server (Debian/Ubuntu or RHEL/Fedora):

```bash
curl -fsSL https://raw.githubusercontent.com/nashcom/crowdsec-tools/main/crdsectl/crdsectl.sh -o crdsectl.sh
sudo bash crdsectl.sh install
```

`install` installs CrowdSec and crowdsec-firewall-bouncer via the system package manager, generates the Domino-specific
acquisition/parser/scenario (matching Domino's `authentication failure using internet password` output log line), and
installs itself to `/usr/local/bin/crdsectl`. Afterward, run `crdsectl status` to check it.

Before a fresh install, `install` checks that `127.0.0.1:8080` - CrowdSec's own documented default local API address -
isn't already taken by something else. That port is a common default for other local dev tools/services too, and a
conflict there means CrowdSec's own service fails to start with a bind error only visible via `journalctl` -
checking first surfaces that clearly, before the package is even installed, rather than after. Only runs on a fresh
install (not on a plain re-run/update against an already-installed CrowdSec, where that port is expected to already
be crowdsec itself).

Three tiers of self-test, from least to most invasive:

- `crdsectl test` - dry run, nothing written anywhere: confirms the parser matches a synthetic line via `cscli explain`.
- `crdsectl blocktest [IP] [duration]` - injects a real decision directly via `cscli decisions add`, bypassing
  log/parser/scenario, to verify decision -> bouncer -> nftables enforcement in isolation. Nftables sync often can't
  be verified inside a container (restricted netfilter access, even `--privileged` - WSL2 in particular) -
  `blocktest` detects this, skips the pointless wait, and instead confirms the decision itself via
  `cscli decisions list`, reporting "NOT VERIFIED (container)" for enforcement rather than a misleading "FAILED".
  On a genuine failure, it also checks whether the IP's octets got reversed in nftables (`2.3.4.10` -> `10.4.3.2`) -
  a real `crowdsec-firewall-bouncer` bug found live (2026-08-22), specific to one machine whose package build had
  an older embedded Go toolchain (`GoVersion 1.22.2`) than a working machine's (`1.25.0`), same bouncer version
  (`v0.0.36`) otherwise. The decision itself was correct the whole time; only the bouncer's nftables write was
  wrong - `blocktest` now reports this distinctly instead of a generic "not found, go check journalctl."
- `crdsectl logtest [IP]` - the real thing: appends real synthetic log lines to the live output log and waits for CrowdSec to genuinely detect, parse, and score them on its own (log -> parser -> scenario -> decision -> bouncer -> nftables, nothing bypassed). Permanently adds lines to the real log file - not undoable.

Alternatively, a piped remote install:

```bash
export CRDSECTL_URL=https://raw.githubusercontent.com/nashcom/crowdsec-tools/main/crdsectl/crdsectl.sh
curl -fsSL "$CRDSECTL_URL" | sudo -E bash -
```

## Reporting to a central hub (optional)

By default an agent runs fully standalone - its own local CrowdSec LAPI, its own decision database, no visibility
beyond this one server. To instead report alerts to, and pull bans from, a shared central hub (`../crdsec-hub`,
see its own README), register this agent against it:

```bash
crdsectl trust <hub-ca-cert-path>     # only if the hub uses a private/self-signed CA
crdsectl register <hub-url> <machine-login> <machine-password> <bouncer-key> [--force]
```

`trust` must run first (if needed) - `register` itself takes no CA argument. `<machine-login>`/`<machine-password>`
and `<bouncer-key>` come from running `../crdsec-hub/crdsec-hub.sh register` (or `addmachine`/`addbouncer`
separately) on the hub, not from this script. Live-tested end to end 2026-08-21: a registered agent's alert reached
the hub and was visible via the hub's own `alerts`/`decisions` commands.

`register` checks it can actually reach `<hub-url>` (including TLS certificate validation) before touching any
config - if you forgot `trust` first, or the URL/network path is wrong, it fails immediately with a clear message
instead of writing config, restarting crowdsec, and only then failing deep in `journalctl -xeu crowdsec` with a
cryptic `x509: certificate signed by unknown authority`.

`register` always checks for a `<file>.local` overlay next to `local_api_credentials.yaml`/
`crowdsec-firewall-bouncer.yaml` and warns if either sets a credential field - CrowdSec layers these on top of the
real config file for local customization that survives a package upgrade, and a stale credential left in one
silently overrides whatever `register` just wrote, with no error anywhere. Found live in production (2026-08-22)
on a machine that had an older CrowdSec install predating `crdsectl`: every re-registration kept failing with
`API error: access forbidden`, even though the real config file and a freshly-issued key were both correct -
untraceable without reading the `.local` file directly, since nothing in the logs points at it. `--force` backs
the `.local` file up and strips just the conflicting credential lines (not the whole file, in case something else
legitimate lives there) so the real config's values actually take effect; without `--force`, it only warns and
leaves the file alone.

This deliberately does not disable the agent's own local CrowdSec LAPI server - on a real deployment (agent and hub
on separate machines) it sits unused but harmless. It only matters when co-testing agent and hub on one machine (see
`../crdsec-hub/README.md`'s networking note).

## Manual ban / unban

Independent of any hub - operates on this agent's own decision database:

```bash
crdsectl block <ip> [duration]      # e.g. crdsectl block 1.2.3.4 1h (default: 4h, cscli's own default)
crdsectl unblock <ip>
crdsectl blocktest [ip] [duration]  # self-test: adds a decision, confirms the bouncer synced it into nftables (default 1.2.3.4, 10m)
```

If this agent is registered against a hub, banning there also works and propagates to every other agent - see
`../crdsec-hub/README.md`'s `ban`/`unban`.

## Files

| File                            | Purpose                                                                                                 |
|---------------------------------|---------------------------------------------------------------------------------------------------------|
| `crdsectl.sh`                   | The actual deliverable. Everything else here is test tooling for it.                                    |
| `Dockerfile`                    | Ubuntu + systemd + dbus, for a real init system to exercise the systemctl/journalctl-backed commands.   |
| `run-install-test-container.sh` | Builds and starts that test container.                                                                  |

## Testing

```bash
./run-install-test-container.sh            # Ubuntu (default)
./run-install-test-container.sh -redhat    # registry.access.redhat.com/ubi10-init instead
./run-install-test-container.sh stop       # docker stop, leaves the container around
./run-install-test-container.sh rm         # docker rm -f, deletes it (image stays)
./run-install-test-container.sh kill       # docker kill, for when "stop" hangs
./run-install-test-container.sh help       # show this option reference
```

`NETWORK_MODE=host` (default) shares the real host's network namespace - `localhost` inside the container reaches
services published on the host (e.g. the crdsec-hub's nginx on :8443), and nftables rules from
`install`/`blocktest` apply to the real host network stack, not a sandbox. `NETWORK_MODE=bridge` instead joins the
shared `crowdsec-net` network (also used by ../crdsec-hub/docker-compose.yml), reaching the hub via its
container name instead of `localhost` - narrower blast radius, but less representative of how a real Domino server
(never on the hub's Docker network) actually reaches it:

```bash
NETWORK_MODE=bridge ./run-install-test-container.sh
```

`run-install-test-container.sh` bind-mounts the repo root (not this directory) at `/local` inside the container, so both `crdsectl.sh` (at
`/local/crdsectl/crdsectl.sh`) and the `notesdata/` test fixture (at `/local/notesdata`, matching
`DOMINO_DATA_PATH`'s default) are visible together.

```bash
bash /local/crdsectl/crdsectl.sh install
```

`--privileged` is required because the firewall bouncer needs to write real nftables rules - this container is not
sandboxed the way a normal Docker container would be, and its rules can affect the host's own network namespace if
it shares one. See `crdsectl.sh blocktest` for a scoped-down way to verify the decision -> nftables path without a
full install.

## Known limitation

Blocking has only been verified from inside this test container, not against real Domino traffic on a real machine.
With `NETWORK_MODE=host` (the default), the bouncer's nftables rules do apply to the real host network stack -
closer to production than the earlier bridge-only setup - but this still hasn't been confirmed to actually protect
a real Domino instance's traffic end to end.
