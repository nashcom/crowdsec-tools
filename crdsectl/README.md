# crdsectl.sh

Installs, configures and operates CrowdSec as a per-service fail2ban replacement, on a single protected server.
Domino (Internet password authentication failures) is the service implemented today.

## Commands

Kept in sync with `crdsectl.sh help` - run that directly if this drifts.

| Command                                           | Description                                                                   |
|---------------------------------------------------|-------------------------------------------------------------------------------|
| *(none)*                                          | Show CrowdSec status                                                          |
| `help`                                            | Show this help                                                                |
| `install [log-file] [token]`                      | Install CrowdSec, bouncer, service config, optional console enroll            |
| `update [log-file]`                               | Update embedded CrowdSec configuration                                        |
| `upgrade`                                         | Update the crdsectl script itself (from GitHub, or run a newer local file)    |
| `test`                                            | Test configuration and parser                                                 |
| `status`                                          | Show CrowdSec status                                                          |
| `alerts`                                          | List CrowdSec alerts                                                          |
| `decisions`                                       | List active CrowdSec decisions                                                |
| `metrics`                                         | Show CrowdSec metrics                                                         |
| `collections`                                     | List installed CrowdSec collections                                           |
| `enroll <token>`                                  | Enroll this instance with the CrowdSec console (SaaS)                         |
| `trust <ca-cert-path>`                            | Trust a self-hosted hub's CA (run before `register`, if needed)               |
| `register <url> <login> <pw> <key>`               | Report to / consume decisions from a self-hosted hub (`--force` overwrites)   |
| `block <IP> [duration]`                           | Add a CrowdSec decision                                                       |
| `unblock <IP>`                                    | Delete CrowdSec decisions for an IP                                           |
| `blocktest [IP] [duration]`                       | Block a test IP and verify nftables (default 1.2.3.4, 10m)                    |
| `logtest [IP]`                                    | Write real test log lines and verify the full log->decision pipeline          |
| `duration [value]`                                | Show or set the default ban duration (e.g. 4h)                                |
| `progressive [on\|off]`                           | Show or set progressive (escalating) ban duration                            |
| `profile`                                         | Open profiles.yaml in $EDITOR (or vi), validate, and restart                  |
| `capi send\|pull [on\|off]`                       | Show or set CAPI signal sharing / blocklist pulling                          |
| `capi register`                                   | Opt in to CrowdSec's Central API (off by default)                             |
| `geoip source [url-prefix]`                       | Show or set geoip-enrich's GeoLite2 mmdb source (or set CRDSECTL_GEOIP_URL)   |
| `firewall`                                        | Show CrowdSec nftables rules                                                  |
| `log [lines]`                                     | Show CrowdSec journal (default: 100 lines)                                    |
| `reload`                                          | Validate and reload CrowdSec                                                  |
| `restart`                                         | Validate and restart CrowdSec and bouncer                                     |
| `systemd [cmd]`                                   | Manage CrowdSec and bouncer services                                          |
| `config`                                          | Show CrowdSec configuration                                                   |
| `version`                                         | Show version information                                                      |

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

To update the `crdsectl` script itself later (distinct from `update`, which regenerates the embedded Domino
config, not this script) - same convention as `install` already uses, no separate argument for which file:

```bash
crdsectl upgrade                    # pulls the latest from GitHub
bash /path/to/newer.sh upgrade      # or from a local file (e.g. one you scp'd over) - run that file directly
```

`upgrade` prefers the script currently being run (`$0`) over a GitHub download - if you've just `git pull`'d or
`scp`'d a newer copy and are running that file directly, it uses that instead of a redundant network fetch (falls
back to GitHub only when `$0` isn't a real file, e.g. a piped install, or is the same file already installed at
`/usr/local/bin/crdsectl`, in which case there's nothing local to compare against). Either way it shows the
actually-installed version (read from disk, not assumed) against the candidate's before applying anything.

Three tiers of self-test, from least to most invasive:

- `crdsectl test` - dry run, nothing written anywhere: confirms the parser matches a synthetic line via `cscli explain`.
- `crdsectl blocktest [IP] [duration]` - injects a real decision directly via `cscli decisions add`, bypassing
  log/parser/scenario, to verify decision -> bouncer -> nftables enforcement in isolation. Nftables sync often can't
  be verified inside a container (restricted netfilter access, even `--privileged` - WSL2 in particular) -
  `blocktest` detects this, skips the pointless wait, and instead confirms the decision itself via
  `cscli decisions list`, reporting "NOT VERIFIED (container)" for enforcement rather than a misleading "FAILED".
  On a genuine failure, it also checks whether the IP's octets got reversed in nftables (`2.3.4.10` -> `10.4.3.2`)
  and reports that distinctly, with a specific fix, instead of a generic "not found, go check journalctl."
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

## Ban duration / progressive ban

Both live in `/etc/crowdsec/profiles.yaml`, applied to both `default_ip_remediation` and `default_range_remediation`
(kept in sync - range-scoped decisions are a real possibility here, e.g. from console/community blocklists, not just
unused boilerplate):

```bash
crdsectl duration          # show the current default ban duration
crdsectl duration 6h       # set it (golang duration format: 4h, 30m, 1h30m, ...)
crdsectl progressive       # show whether progressive (escalating) ban duration is enabled
crdsectl progressive on    # enable it - uses CrowdSec's own stock formula, unchanged:
                            #   Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
                            #   (1st offense: base duration, 2nd: 2x, 3rd: 3x, ...)
crdsectl progressive off   # disable it
crdsectl profile           # open profiles.yaml directly in $EDITOR (or vi), validate, and restart
```

## Central API (CAPI)

CAPI is CrowdSec's own centralized cloud service, distinct from the LAPI (local API) that this agent's own
`crowdsec` and bouncer talk to. LAPI is this instance's own decisions and enforcement; CAPI is the optional
global CrowdSec network - pushing your own alerts up (`Signal sharing`) and pulling down the community blocklist
and any Console-managed blocklists you've subscribed to.

**Off by default.** The `crowdsec` package's own postinst auto-registers with CAPI unless
`/etc/crowdsec/online_api_credentials.yaml` already exists and is non-empty (verified against Debian's actual
postinst script) - `install` pre-creates a placeholder file for exactly that reason, so a fresh `crdsectl install`
never registers with a third party without an explicit choice. Opt in any time afterward:

```bash
crdsectl capi register     # register for real, and enable sharing + pulling in one step
crdsectl capi send on|off  # signal sharing only
crdsectl capi pull on|off  # community + console blocklist pulling, always set together
```

`crdsectl status` includes a "CrowdSec Central API" block - `Connection`, `Signal sharing`, `Community blocklist`,
`Console blocklists`. The three enabled/disabled fields are read directly from `config.yaml` (reliable), not
parsed from `cscli capi status`'s plain-text output (it doesn't support `--output json`, confirmed live) - that
command is only used for the live `Connection` check, and only attempted when something's actually enabled to
check, so a genuinely disabled setup never shows a misleading `FAILED`/`unknown`.

If the ip and range profiles have diverged (e.g. from a manual `profile` edit), `duration`/`progressive` with no
argument shows both as `ip / range` instead of silently only reporting the ip value.

`install` and `update` both enable progressive ban by default (base duration untouched) every time they run -
including overriding an explicit `progressive off`, since there's no way to distinguish "still at CrowdSec's stock
default" from "an admin deliberately turned it off" from the file content alone. If you don't want progressive ban,
run `crdsectl progressive off` again after any `update`.

## GeoIP data

`geoip-enrich` (a CrowdSec hub item most collections depend on) downloads MaxMind GeoLite2 `.mmdb` files from
CrowdSec's own CDN (`hub-data.crowdsec.net`) by default. To serve them from your own repository instead:

```bash
crdsectl geoip source                                  # show the current source_url(s)
crdsectl geoip source https://mirror.example.com/geoip  # point both City and ASN mmdb at your own mirror
```

A single prefix is applied to both entries (`<prefix>/GeoLite2-City.mmdb`, `<prefix>/GeoLite2-ASN.mmdb`), matching
CrowdSec's own `.../mmdb_update/<file>` layout. For unattended deployment, set `CRDSECTL_GEOIP_URL` in the
environment instead - `update` applies it automatically every run, the same pattern as `DOMINO_OUTPUT_LOG`.

This edits `geoip-enrich.yaml` in place rather than regenerating it, since (unlike the Domino acquisition/parser/
scenario files) it's hub-installed content crdsectl doesn't own. Verified against CrowdSec's own source
(`pkg/hubops`): a locally-modified ("tainted") item is skipped by `cscli hub upgrade`/`cscli parsers upgrade`
unless `--force` is passed, so the override survives normal use - only an explicit `--force` upgrade of that item
would revert it to CrowdSec's stock URL.

`crdsectl status` includes a "GeoIP data" block showing each `.mmdb`'s local path, size, last-updated time, and
configured source - read live from `geoip-enrich.yaml` and the data directory, so it reflects whatever source is
currently set.

## Files

| File                              | Purpose                                                                                                   |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------|
| --------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `crdsectl.sh`                     | The actual deliverable. Everything else here is test tooling for it.                                      |
| `Dockerfile`                      | Ubuntu + systemd + dbus, for a real init system to exercise the systemctl/journalctl-backed commands.     |
| `run-install-test-container.sh`   | Builds and starts that test container.                                                                    |

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
