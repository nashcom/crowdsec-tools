#!/bin/bash

###########################################################################
#                                                                         #
# crdsectl - CrowdSec-based per-service auth-failure protection script    #
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
# Version 0.9.7                                                           #
#                                                                         #
# Install, configure and operate CrowdSec as a per-service brute-force /  #
# auth-failure guard. Manages two components: "crowdsec" (detects,        #
# scores, decides) and "crowdsec-firewall-bouncer" (enforces via          #
# nftables). Not tied to any one service - HCL Domino is the first one    #
# implemented, because that's the immediate need. See README.md for the   #
# full command reference and the currently-implemented feature list.      #
#                                                                         #
###########################################################################

CRDSECTL_VERSION="0.9.7"
CRDSECTL_CONFIG_VERSION="1"

CROWDSEC_SERVICE="crowdsec"
BOUNCER_SERVICE="crowdsec-firewall-bouncer"

CROWDSEC_ACQUIS_DIR="/etc/crowdsec/acquis.d"
CROWDSEC_PARSER_DIR="/etc/crowdsec/parsers/s01-parse"
CROWDSEC_SCENARIO_DIR="/etc/crowdsec/scenarios"
CROWDSEC_PROFILES_FILE="/etc/crowdsec/profiles.yaml"
CROWDSEC_CONFIG_FILE="/etc/crowdsec/config.yaml"

CRDSECTL_ACQUIS_FILE="${CROWDSEC_ACQUIS_DIR}/domino.yaml"
CRDSECTL_PARSER_FILE="${CROWDSEC_PARSER_DIR}/domino-auth.yaml"
CRDSECTL_SCENARIO_FILE="${CROWDSEC_SCENARIO_DIR}/domino-auth-bf.yaml"

CRDSECTL_INSTALL_PATH="/usr/local/bin/crdsectl"

# CRDSECTL_URL is only used for a piped remote install, e.g.:
#   export CRDSECTL_URL=https://raw.githubusercontent.com/nashcom/crowdsec-tools/main/crdsectl/crdsectl.sh; curl -fsSL "$CRDSECTL_URL" | bash -
# When piped this way, $0 is just the shell's own name (e.g. "bash"), not a
# real file, so install_self() re-downloads a real copy from CRDSECTL_URL to
# install. Set here only as documentation; the actual value always comes
# from the environment.
CRDSECTL_URL="${CRDSECTL_URL:-}"

# DOMINO_CONFIG_FILE is the Domino start-script's own config file, read
# (never written) to pick up DOMINO_DATA_PATH and DOMINO_OUTPUT_LOG - the
# same env var name the start script itself uses, so an existing Domino
# deployment's own config is picked up automatically without needing a
# crdsectl-specific override. It won't exist in a container-based Domino
# deployment, so DOMINO_CONFIG_FILE, DOMINO_DATA_PATH and DOMINO_OUTPUT_LOG
# can all be pre-exported instead, e.g.:
#   DOMINO_OUTPUT_LOG=/local/notesdata/notes.log crdsectl.sh status
# DOMINO_OUTPUT_LOG defaults to DOMINO_DATA_PATH/notes.log when not
# explicitly set (by the start script's own config or an override).
DOMINO_CONFIG_FILE="${DOMINO_CONFIG_FILE:-/etc/sysconfig/rc_domino_config}"

# Matches the real Domino output log wording (confirmed against a captured
# line): "<timestamp> http: <user> [<ip>] authentication failure using
# internet password". Uses an RFC 5737 documentation IP, not a real address.
CRDSECTL_TEST_IP="192.0.2.10"
CRDSECTL_TEST_AUTH_LINE="08/08/2026 09:30:00 PM  http: user [${CRDSECTL_TEST_IP}] authentication failure using internet password"

SUDO=""
PKG_MGR=""
EDIT_COMMAND="${EDIT_COMMAND:-vi}"


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


log_info()
{
  echo "Info: $*"
}


os_pretty_name()
{
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    (. /etc/os-release && echo "$PRETTY_NAME")
    return
  fi

  echo "unknown"
}


have_command()
{
  command -v "$1" >/dev/null 2>&1
}


# Nftables enforcement can genuinely fail to sync inside a container - even
# --privileged - due to restricted netfilter/kernel access (WSL2 in
# particular). That's an environment limitation, not a crdsectl or bouncer
# bug, so callers use this to give a softer, more accurate message instead
# of a scary unqualified "FAILED" that leaves an admin thinking something
# is actually broken.
in_container()
{
  [ -e /.dockerenv ] && return 0
  grep -qE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null
}


setup_sudo()
{
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    return 0
  fi

  if have_command sudo; then
    SUDO="sudo"
    return 0
  fi

  log_err "This operation requires root privileges and sudo is not available."
  return 1
}


require_root()
{
  setup_sudo || return 1

  if [ -n "$SUDO" ]; then
    $SUDO -v || return 1
  fi
}


detect_pkg_mgr()
{
  if have_command apt-get; then
    PKG_MGR="apt"
    return 0
  fi

  if have_command dnf; then
    PKG_MGR="dnf"
    return 0
  fi

  if have_command yum; then
    PKG_MGR="yum"
    return 0
  fi

  return 1
}


pkg_update()
{
  case "$PKG_MGR" in
    apt)
      $SUDO apt-get update
      ;;

    dnf)
      $SUDO dnf makecache
      ;;

    yum)
      $SUDO yum makecache
      ;;

    *)
      log_err "Unknown package manager: '$PKG_MGR'"
      return 1
      ;;
  esac
}


pkg_install()
{
  case "$PKG_MGR" in
    apt)
      $SUDO apt-get install -y "$@"
      ;;

    dnf)
      $SUDO dnf install -y "$@"
      ;;

    yum)
      $SUDO yum install -y "$@"
      ;;

    *)
      log_err "Unknown package manager: '$PKG_MGR'"
      return 1
      ;;
  esac
}

nsh_cmp()
{
  if [ -z "$1" ] || [ -z "$2" ]; then
    return 1
  fi

  if [ ! -e "$1" ] || [ ! -e "$2" ]; then
    return 1
  fi

  # Third arg "sudo" reads via $SUDO - only needed when a file was cp -a'd
  # from a root-owned source with restrictive permissions (e.g. edit_profiles'
  # pre_edit snapshot). Most callers compare world-readable config files and
  # don't need it.
  local reader=""
  [ "$3" = "sudo" ] && reader="$SUDO"

  if have_command cmp; then
    $reader cmp -s "$1" "$2"
    return $?
  fi

  local hash1
  local hash2

  hash1=$($reader sha256sum "$1" | cut -d" " -f1)
  hash2=$($reader sha256sum "$2" | cut -d" " -f1)

  [ "$hash1" = "$hash2" ]
}


###############################################################################
# Domino configuration
###############################################################################

load_domino_config()
{
  if [ -r "$DOMINO_CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$DOMINO_CONFIG_FILE"
  fi

  if [ -z "$DOMINO_DATA_PATH" ]; then
    DOMINO_DATA_PATH="/local/notesdata"
  fi

  if [ -z "$DOMINO_OUTPUT_LOG" ]; then
    DOMINO_OUTPUT_LOG="${DOMINO_DATA_PATH}/notes.log"
  fi
}


###############################################################################
# Embedded CrowdSec configuration
###############################################################################

generate_acquisition()
{
  cat <<EOF
# ---------------------------------------------------------------------------
# HCL Domino CrowdSec integration
# Generated by crdsectl ${CRDSECTL_VERSION}
# Configuration version ${CRDSECTL_CONFIG_VERSION}
# Do not manually modify this file. Use "crdsectl update" to regenerate it.
# ---------------------------------------------------------------------------

filenames:
  - ${DOMINO_OUTPUT_LOG}

labels:
  type: domino
EOF
}


generate_parser()
{
  cat <<'EOF'
# ---------------------------------------------------------------------------
# HCL Domino CrowdSec parser
# Managed by crdsectl
# ---------------------------------------------------------------------------

name: domino-auth
description: "Parse HCL Domino authentication failures"

filter: "evt.Line.Labels.type == 'domino'"

onsuccess: next_stage

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
EOF
}


generate_scenario()
{
  cat <<'EOF'
# ---------------------------------------------------------------------------
# HCL Domino CrowdSec scenario
# Managed by crdsectl
# ---------------------------------------------------------------------------

type: leaky
name: domino-auth-bf
description: "Detect HCL Domino authentication brute force attempts"

filter: "evt.Meta.log_type == 'domino_failed_auth'"

groupby: evt.Meta.source_ip

capacity: 5
leakspeed: "5m"
blackhole: 5m

labels:
  service: domino
  type: bruteforce
  remediation: true
EOF
}


###############################################################################
# Managed configuration installation
###############################################################################

make_backup()
{
  local target="$1"
  local backup="$2"

  if $SUDO test -e "$target"; then
    $SUDO cp -a "$target" "$backup" || return 1
    return 0
  fi

  return 2
}


restore_file()
{
  local target="$1"
  local backup="$2"
  local existed="$3"

  if [ "$existed" = "yes" ]; then
    $SUDO cp -a "$backup" "$target"
  else
    $SUDO rm -f "$target"
  fi
}


install_generated_file()
{
  local source="$1"
  local target="$2"
  local mode="${3:-0644}"

  if $SUDO test -e "$target"; then
    if nsh_cmp "$source" "$target"; then
      echo "[$target] unchanged"
      return 0
    fi
  fi

  $SUDO install -o root -g root -m "$mode" "$source" "$target" || return 1
  echo "[$target] updated"
  return 2
}


install_self()
{
  # $0 is already a full, usable path both when run directly (./crdsectl.sh)
  # and when run as a bare command found via PATH (bash resolves it before
  # the script sees it). It is NOT a real file only when the script is
  # piped into a shell (e.g. curl ... | sh -s -- install), where $0 is just
  # the interpreter's own name (e.g. "sh") - resolving that via "command -v"
  # would find the interpreter's real binary and copy THAT in as
  # /usr/local/bin/crdsectl, which is why there is no such fallback here.
  # In that case, CRDSECTL_URL (if set) is used to re-download a real copy.
  local source_path="$0"
  local tmp_download=""

  if [ ! -f "$source_path" ]; then
    if [ -z "$CRDSECTL_URL" ]; then
      log_err "Cannot self-install: '$0' is not a regular file. If you piped this script into a shell, either save it to a file first and run install from that file, or set CRDSECTL_URL to a URL this script can be re-downloaded from."
      return 1
    fi

    echo
    echo "Detected a piped install (no local script file) - downloading crdsectl from CRDSECTL_URL: ${CRDSECTL_URL}"
    echo

    tmp_download=$(mktemp) || return 1

    if ! curl -fsSL "$CRDSECTL_URL" -o "$tmp_download"; then
      log_err "Failed to download crdsectl from CRDSECTL_URL (${CRDSECTL_URL})."
      rm -f "$tmp_download"
      return 1
    fi

    source_path="$tmp_download"
  else
    echo "Installing crdsectl command from: ${source_path}"
  fi

  install_generated_file "$source_path" "$CRDSECTL_INSTALL_PATH" 0755
  local rc=$?

  [ -n "$tmp_download" ] && rm -f "$tmp_download"

  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    return 1
  fi

  return 0
}


# Updates the installed crdsectl.sh binary itself (distinct from "update",
# which regenerates the embedded Domino config, not this script). Same
# source convention as install_self(): no separate argument to say which
# file - the source is inferred from how this script is invoked ($0). To
# upgrade from a specific local file (e.g. one just scp'd over), run that
# file directly ("bash /path/to/newer.sh upgrade"), the same way you'd
# already run "bash newer.sh install" to self-install from it - not a
# second argument to the subcommand. $0 is skipped when it's the
# already-installed file itself (running the installed "crdsectl" command
# with no args would otherwise compare it against itself, always
# "unchanged", not useful) - falls back to a download from CRDSECTL_URL
# (default: the real GitHub repo) in that case. Always shows the
# installed vs. candidate version before applying, so a machine you're
# not actively watching doesn't silently jump versions with no visibility
# into what changed. install_generated_file's own content diff still
# governs whether anything is actually written - this just makes the
# version difference visible on top of that.
upgrade_self()
{
  require_root || return 1

  local candidate_path
  local tmp_download=""

  if [ -f "$0" ] && [ "$0" != "$CRDSECTL_INSTALL_PATH" ]; then
    candidate_path="$0"
    echo "Checking version from the running script: ${0}"
  else
    local url="${CRDSECTL_URL:-https://raw.githubusercontent.com/nashcom/crowdsec-tools/main/crdsectl/crdsectl.sh}"
    echo "Checking version from: ${url}"

    tmp_download=$(mktemp) || return 1

    if ! curl -fsSL "$url" -o "$tmp_download"; then
      log_err "Failed to download crdsectl from ${url}."
      rm -f "$tmp_download"
      return 1
    fi

    candidate_path="$tmp_download"
  fi

  local candidate_version
  candidate_version=$(grep -m1 '^CRDSECTL_VERSION=' "$candidate_path" | sed -E 's/^CRDSECTL_VERSION="([^"]*)"$/\1/')

  if [ -z "$candidate_version" ]; then
    log_err "Could not determine a version from that file - doesn't look like a valid crdsectl.sh."
    rm -f "$tmp_download"
    return 1
  fi

  # Deliberately read from $CRDSECTL_INSTALL_PATH on disk, not the
  # $CRDSECTL_VERSION constant of the script currently running - those
  # differ whenever $0 is a newer file than what's actually installed
  # (e.g. just git-pulled a newer copy and running it directly), and
  # trusting the constant would show the wrong "Installed version".
  local installed_version="not installed yet"
  if [ -f "$CRDSECTL_INSTALL_PATH" ]; then
    installed_version=$(grep -m1 '^CRDSECTL_VERSION=' "$CRDSECTL_INSTALL_PATH" | sed -E 's/^CRDSECTL_VERSION="([^"]*)"$/\1/')
    [ -z "$installed_version" ] && installed_version="unknown"
  fi

  echo
  printf "%-24s :  %s\n" "Installed version" "$installed_version"
  printf "%-24s :  %s\n" "Available version" "$candidate_version"
  echo

  install_generated_file "$candidate_path" "$CRDSECTL_INSTALL_PATH" 0755
  local rc=$?

  rm -f "$tmp_download"

  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    return 1
  fi

  if [ $rc -eq 2 ]; then
    echo
    echo "Updated to ${candidate_version}."
  fi

  echo

  return 0
}


update_domino_config()
{
  local log_file_override="$1"

  require_root || return 1
  load_domino_config

  # Precedence: explicit command-line argument, then DOMINO_OUTPUT_LOG
  # environment variable (applied by load_domino_config), then the
  # DOMINO_DATA_PATH-derived default.
  if [ -n "$log_file_override" ]; then
    DOMINO_OUTPUT_LOG="$log_file_override"
  fi

  if ! have_command crowdsec; then
    log_err "CrowdSec is not installed."
    return 1
  fi

  local changed=0

  # Domino not installed on this host yet (eg crdsectl installed ahead of
  # Domino itself) - skip wiring up the acquisition/parser/scenario, rather
  # than pointing them at a log that doesn't exist. Re-running 'update'
  # once Domino is there picks it up; leaves any already-installed files
  # untouched either way.
  if [ ! -r "$DOMINO_OUTPUT_LOG" ]; then
    echo
    echo "Domino output log (${DOMINO_OUTPUT_LOG}) not found or not readable - skipping Domino acquisition/parser/scenario setup. Run 'crdsectl update' once Domino is installed."
  else
    local tmpdir
    tmpdir=$(mktemp -d) || return 1

    local acquis_tmp="${tmpdir}/domino.yaml"
    local parser_tmp="${tmpdir}/domino-auth.yaml"
    local scenario_tmp="${tmpdir}/domino-auth-bf.yaml"

    generate_acquisition > "$acquis_tmp"
    generate_parser > "$parser_tmp"
    generate_scenario > "$scenario_tmp"

    $SUDO mkdir -p "$CROWDSEC_ACQUIS_DIR" \
            "$CROWDSEC_PARSER_DIR" \
            "$CROWDSEC_SCENARIO_DIR" || {
      rm -rf "$tmpdir"
      return 1
    }

    local backup_dir="${tmpdir}/backup"
    mkdir -p "$backup_dir"

    local acquis_existed="no"
    local parser_existed="no"
    local scenario_existed="no"

    make_backup "$CRDSECTL_ACQUIS_FILE" "${backup_dir}/domino.yaml"
    [ $? -eq 0 ] && acquis_existed="yes"

    make_backup "$CRDSECTL_PARSER_FILE" "${backup_dir}/domino-auth.yaml"
    [ $? -eq 0 ] && parser_existed="yes"

    make_backup "$CRDSECTL_SCENARIO_FILE" "${backup_dir}/domino-auth-bf.yaml"
    [ $? -eq 0 ] && scenario_existed="yes"

    local rc

    install_generated_file "$acquis_tmp" "$CRDSECTL_ACQUIS_FILE"
    rc=$?
    [ $rc -eq 2 ] && changed=1
    if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
      rm -rf "$tmpdir"
      return 1
    fi

    install_generated_file "$parser_tmp" "$CRDSECTL_PARSER_FILE"
    rc=$?
    [ $rc -eq 2 ] && changed=1
    if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
      restore_file "$CRDSECTL_ACQUIS_FILE" "${backup_dir}/domino.yaml" "$acquis_existed"
      rm -rf "$tmpdir"
      return 1
    fi

    install_generated_file "$scenario_tmp" "$CRDSECTL_SCENARIO_FILE"
    rc=$?
    [ $rc -eq 2 ] && changed=1
    if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
      restore_file "$CRDSECTL_ACQUIS_FILE" "${backup_dir}/domino.yaml" "$acquis_existed"
      restore_file "$CRDSECTL_PARSER_FILE" "${backup_dir}/domino-auth.yaml" "$parser_existed"
      rm -rf "$tmpdir"
      return 1
    fi

    echo
    echo "Validating CrowdSec configuration..."

    if ! $SUDO crowdsec -t; then
      echo
      log_err "CrowdSec configuration validation failed. Restoring previous configuration."

      restore_file "$CRDSECTL_ACQUIS_FILE" "${backup_dir}/domino.yaml" "$acquis_existed"
      restore_file "$CRDSECTL_PARSER_FILE" "${backup_dir}/domino-auth.yaml" "$parser_existed"
      restore_file "$CRDSECTL_SCENARIO_FILE" "${backup_dir}/domino-auth-bf.yaml" "$scenario_existed"

      rm -rf "$tmpdir"
      return 1
    fi

    rm -rf "$tmpdir"
  fi

  if enable_progressive_default; then
    changed=1
  fi

  if [ "$changed" -eq 1 ]; then
    echo
    echo "CrowdSec configuration updated."
    return 2
  fi

  echo
  echo "CrowdSec configuration is already current."
  return 0
}


###############################################################################
# Installation
###############################################################################

# Pre-flight check for install_crowdsec(): CrowdSec's local API defaults to
# binding 127.0.0.1:8080 (confirmed against docs.crowdsec.net, not
# assumed) - a very commonly-squatted port for other local dev
# tools/services. If something else already has it, crowdsec fails to
# start with a bind error that's only visible via journalctl, discovered
# live in production once already (a stale leftover container holding the
# port). Checking here gives a clear message before the package is even
# installed, matching register_lapi's own check_hub_reachable pre-flight.
# Uses bash's own /dev/tcp (no dependency on ss/netstat, which may not be
# installed yet this early in a fresh install).
check_lapi_port_free()
{
  local host="127.0.0.1"
  local port="8080"

  if timeout 1 bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    log_err "Something is already listening on ${host}:${port} - CrowdSec's local API defaults to this address and will fail to start there. Free the port first (eg 'ss -ltnp | grep ${port}' to find what's using it), or re-run once it's clear."
    return 1
  fi

  return 0
}


install_crowdsec()
{
  local log_file_override="$1"
  local enroll_token="$2"

  require_root || return 1

  if ! detect_pkg_mgr; then
    log_err "Version ${CRDSECTL_VERSION} currently supports Debian/Ubuntu (apt) and RHEL/Fedora (dnf/yum) installations only."
    return 1
  fi

  echo
  print_delim
  echo "Installing CrowdSec"
  print_delim
  echo

  install_self || return 1

  local fresh_install="no"

  if ! have_command crowdsec || ! have_command cscli; then
    fresh_install="yes"

    # Only checked here (fresh install) - once crowdsec is already
    # installed, whatever's listening on 8080 is expected to be crowdsec
    # itself, not a conflict, and a plain "install" re-run/update should
    # not fail on that.
    check_lapi_port_free || return 1

    echo "Installing CrowdSec repository..."

    pkg_update || return 1

    if ! have_command curl; then
      pkg_install curl || return 1
    fi

    # Not fatal if this fails - nsh_cmp() falls back to sha256sum without it.
    have_command cmp || pkg_install diffutils

    local install_script
    install_script=$(mktemp) || return 1

    if ! curl -fsSL https://install.crowdsec.net -o "$install_script"; then
      log_err "Failed to download CrowdSec install script from install.crowdsec.net."
      rm -f "$install_script"
      return 1
    fi

    $SUDO sh "$install_script"
    local install_rc=$?
    rm -f "$install_script"

    if [ $install_rc -ne 0 ]; then
      log_err "CrowdSec install script failed."
      return 1
    fi
  else
    log_info "CrowdSec already installed."
  fi

  # Both apt and dnf/yum repos split -iptables / -nftables variants; this
  # project's scope is nftables, so always pick that variant explicitly.
  local bouncer_package="crowdsec-firewall-bouncer-nftables"

  pkg_update || return 1

  # CAPI is off by default (opt in via "crdsectl capi register") - the
  # skip mechanism differs by package manager: apt decides from the
  # "crowdsec/capi" debconf boolean, dnf/yum from whether the credentials
  # file already exists.
  if [ "$fresh_install" = "yes" ]; then
    case "$PKG_MGR" in
      apt)
        export DEBIAN_FRONTEND=noninteractive
        echo "crowdsec crowdsec/capi boolean false" | $SUDO debconf-set-selections
        ;;
      dnf|yum)
        $SUDO mkdir -p /etc/crowdsec || return 1
        echo "# CAPI registration skipped by crdsectl install - run 'crdsectl capi register' to opt in" | $SUDO tee /etc/crowdsec/online_api_credentials.yaml >/dev/null
        ;;
    esac
  fi

  # Install and start crowdsec on its own first. The bouncer package's own
  # post-install step registers itself with crowdsec's local API - if
  # crowdsec isn't already up when that runs, registration silently fails
  # and the bouncer is left with an unusable placeholder API key.
  pkg_install crowdsec || return 1

  $SUDO systemctl enable "$CROWDSEC_SERVICE" || return 1
  $SUDO systemctl restart "$CROWDSEC_SERVICE" || return 1

  pkg_install "$bouncer_package" || return 1

  update_domino_config "$log_file_override"
  local update_rc=$?

  if [ $update_rc -ne 0 ] && [ $update_rc -ne 2 ]; then
    return 1
  fi

  $SUDO systemctl enable "$BOUNCER_SERVICE" || return 1

  $SUDO systemctl restart "$CROWDSEC_SERVICE" || return 1
  $SUDO systemctl restart "$BOUNCER_SERVICE" || return 1

  if [ -n "$enroll_token" ]; then
    echo
    enroll_console "$enroll_token" || return 1
  fi

  echo
  print_delim
  echo "Installation completed"
  print_delim
  echo

  show_status
}


###############################################################################
# Status / diagnostics
###############################################################################

service_state()
{
  local service="$1"

  if systemctl is-active --quiet "$service" 2>/dev/null; then
    echo "running"
  else
    echo "not running"
  fi
}


enabled_state()
{
  local service="$1"

  if systemctl is-enabled --quiet "$service" 2>/dev/null; then
    echo "enabled"
  else
    echo "not enabled"
  fi
}


file_state()
{
  if [ -r "$1" ]; then
    echo "present"
  else
    echo "missing"
  fi
}


# The path CrowdSec is actually watching, read back out of the generated
# acquis.d/domino.yaml - distinct from $DOMINO_OUTPUT_LOG, which is only
# what load_domino_config() would compute *right now* from the
# environment/rc_domino_config. Those two can genuinely diverge (e.g.
# DOMINO_DATA_PATH changed in rc_domino_config since the last "update")
# - status shows both if they differ, rather than silently only ever
# reporting the live-computed guess as if it were the real, running state.
get_configured_output_log()
{
  $SUDO test -e "$CRDSECTL_ACQUIS_FILE" || return 1
  $SUDO awk '/^filenames:/{getline; sub(/^[[:space:]]*-[[:space:]]*/,""); print; exit}' "$CRDSECTL_ACQUIS_FILE"
}


###############################################################################
# Ban duration / progressive ban (profiles.yaml). Applied to both
# default_ip_remediation and default_range_remediation, kept in sync -
# unlike notifications, range-scoped decisions (e.g. from console/
# community blocklists) are a real possibility here, not just unused
# boilerplate. duration/progressive keep both in sync, but a manual
# "profile" edit could still make them diverge - the getters below report
# both and format_*() shows "ip / range" whenever they differ, so a
# divergence is visible instead of silently only showing the ip value.
###############################################################################

get_ban_duration_ip()
{
  $SUDO test -e "$CROWDSEC_PROFILES_FILE" || return 1
  $SUDO awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_ip_remediation/ { found = 1 }
    found && /^[[:space:]]*duration:/ { print $2; exit }
  ' "$CROWDSEC_PROFILES_FILE"
}


get_ban_duration_range()
{
  $SUDO test -e "$CROWDSEC_PROFILES_FILE" || return 1
  $SUDO awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_range_remediation/ { found = 1 }
    found && /^[[:space:]]*duration:/ { print $2; exit }
  ' "$CROWDSEC_PROFILES_FILE"
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
  $SUDO test -e "$CROWDSEC_PROFILES_FILE" || return 1

  if $SUDO awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_ip_remediation/ { found = 1 }
    found { print }
  ' "$CROWDSEC_PROFILES_FILE" | grep -q '^duration_expr:'; then
    echo "enabled"
  else
    echo "disabled"
  fi
}


get_progressive_state_range()
{
  $SUDO test -e "$CROWDSEC_PROFILES_FILE" || return 1

  if $SUDO awk '
    /^---$/ { found = 0 }
    /^[[:space:]]*name:[[:space:]]*default_range_remediation/ { found = 1 }
    found { print }
  ' "$CROWDSEC_PROFILES_FILE" | grep -q '^duration_expr:'; then
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

  if ! $SUDO test -e "$CROWDSEC_PROFILES_FILE"; then
    log_err "${CROWDSEC_PROFILES_FILE} not found."
    return 1
  fi

  if [ -z "$new_duration" ]; then
    echo "Default ban duration: $(format_ban_duration)"
    return 0
  fi

  require_root || return 1

  if ! echo "$new_duration" | grep -Eq '^([0-9]+(h|m|s))+$'; then
    log_err "Invalid duration '${new_duration}' - expected a golang duration like '4h', '30m', '1h30m'."
    return 1
  fi

  local tmp
  tmp=$(mktemp) || return 1

  $SUDO sed "s/^\([[:space:]]*duration: \).*/\1${new_duration}/" "$CROWDSEC_PROFILES_FILE" > "$tmp"

  if nsh_cmp "$tmp" "$CROWDSEC_PROFILES_FILE"; then
    rm -f "$tmp"
    echo "Default ban duration is already ${new_duration}."
    return 0
  fi

  local backup="${CROWDSEC_PROFILES_FILE}.bak"
  $SUDO cp -a "$CROWDSEC_PROFILES_FILE" "$backup"
  $SUDO cp "$tmp" "$CROWDSEC_PROFILES_FILE"
  rm -f "$tmp"

  echo "Default ban duration set to ${new_duration} (backup: ${backup})."
  echo "Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


# Silent, non-restarting variant used by update_domino_config() (and so
# install_crowdsec(), which calls it) to enforce progressive ban as the
# shipped default - re-asserted on every install/update, deliberately
# overriding an explicit "progressive off" too (accepted tradeoff: no way
# to tell "still at stock default" apart from "admin turned it off" from
# file content alone). Only touches duration_expr, never duration itself.
# Returns 0 if it changed something (caller must restart), 1 otherwise.
enable_progressive_default()
{
  $SUDO test -e "$CROWDSEC_PROFILES_FILE" || return 1

  local tmp
  tmp=$(mktemp) || return 1

  $SUDO sed 's/^#duration_expr:/duration_expr:/' "$CROWDSEC_PROFILES_FILE" > "$tmp"

  if nsh_cmp "$tmp" "$CROWDSEC_PROFILES_FILE"; then
    rm -f "$tmp"
    return 1
  fi

  local backup="${CROWDSEC_PROFILES_FILE}.bak"
  $SUDO cp -a "$CROWDSEC_PROFILES_FILE" "$backup"
  $SUDO cp "$tmp" "$CROWDSEC_PROFILES_FILE"
  rm -f "$tmp"

  echo "profiles.yaml: progressive ban enabled by default (was disabled - backup at ${backup})."
  return 0
}


show_or_set_progressive()
{
  local action="$1"

  if ! $SUDO test -e "$CROWDSEC_PROFILES_FILE"; then
    log_err "${CROWDSEC_PROFILES_FILE} not found."
    return 1
  fi

  if [ -z "$action" ]; then
    echo "Progressive ban: $(format_progressive_state)"
    return 0
  fi

  case "$action" in
    on|off) ;;
    *)
      log_err "Usage: crdsectl progressive [on|off]"
      return 1
      ;;
  esac

  require_root || return 1

  local tmp
  tmp=$(mktemp) || return 1

  if [ "$action" = "on" ]; then
    $SUDO sed 's/^#duration_expr:/duration_expr:/' "$CROWDSEC_PROFILES_FILE" > "$tmp"
  else
    $SUDO sed 's/^duration_expr:/#duration_expr:/' "$CROWDSEC_PROFILES_FILE" > "$tmp"
  fi

  if nsh_cmp "$tmp" "$CROWDSEC_PROFILES_FILE"; then
    rm -f "$tmp"
    echo "Progressive ban is already ${action}."
    return 0
  fi

  local backup="${CROWDSEC_PROFILES_FILE}.bak"
  $SUDO cp -a "$CROWDSEC_PROFILES_FILE" "$backup"
  $SUDO cp "$tmp" "$CROWDSEC_PROFILES_FILE"
  rm -f "$tmp"

  echo "Progressive ban turned ${action} (backup: ${backup})."
  echo "Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


edit_profiles()
{
  require_root || return 1

  if ! $SUDO test -e "$CROWDSEC_PROFILES_FILE"; then
    log_err "${CROWDSEC_PROFILES_FILE} not found."
    return 1
  fi

  local editor="${EDITOR:-vi}"

  if ! have_command "$editor"; then
    log_err "Editor '${editor}' not found. Set \$EDITOR or install vi."
    return 1
  fi

  local pre_edit
  pre_edit=$(mktemp) || return 1
  $SUDO cp -a "$CROWDSEC_PROFILES_FILE" "$pre_edit"

  $SUDO "$editor" "$CROWDSEC_PROFILES_FILE"

  if nsh_cmp "$pre_edit" "$CROWDSEC_PROFILES_FILE" sudo; then
    rm -f "$pre_edit"
    echo "No changes made."
    return 0
  fi

  if ! $SUDO crowdsec -t >/dev/null 2>&1; then
    log_err "New configuration failed validation - restoring previous version."
    $SUDO cp -a "$pre_edit" "$CROWDSEC_PROFILES_FILE"
    rm -f "$pre_edit"
    $SUDO crowdsec -t
    return 1
  fi

  # Only overwrite the persistent .bak once the edit is confirmed real and
  # valid - it's the last-known-good config, not a scratch file, so a
  # no-op or rejected edit must leave whatever backup was already there.
  local backup="${CROWDSEC_PROFILES_FILE}.bak"
  $SUDO cp -a "$pre_edit" "$backup"
  rm -f "$pre_edit"

  echo "profiles.yaml updated (backup: ${backup})."
  echo "Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


###############################################################################
# CAPI send/pull toggles (config.yaml's api.server.online_client block):
#   online_client:
#     sharing: true|false      # non-inverted; defaults true when omitted
#     pull:
#       community: true|false  # "capi pull" always sets both together
#       blocklists: true|false
# Edits are scoped to lines inside online_client: (by indentation), not a
# blind key-name match - "credentials_path" also appears under api.client,
# so an unscoped match would hit the wrong one.
###############################################################################

get_capi_sharing()
{
  $SUDO test -e "$CROWDSEC_CONFIG_FILE" || return 1

  $SUDO awk '
    {
      match($0, /^[ ]*/)
      indent = RLENGTH
      stripped = $0
      gsub(/^[ ]*/, "", stripped)
    }
    /^[[:space:]]*online_client:/ { in_block = 1; block_indent = indent; next }
    in_block && stripped != "" && indent <= block_indent { in_block = 0 }
    in_block && $0 ~ /^[[:space:]]*sharing:/ {
      val = $0
      sub(".*sharing:[[:space:]]*", "", val)
      print val
      found = 1
      exit
    }
    END { if (!found) print "true" }
  ' "$CROWDSEC_CONFIG_FILE"
}


set_capi_sharing()
{
  local value="$1"

  local tmp
  tmp=$(mktemp) || return 1

  $SUDO awk -v val="$value" '
    {
      match($0, /^[ ]*/)
      indent = RLENGTH
      stripped = $0
      gsub(/^[ ]*/, "", stripped)
    }
    /^[[:space:]]*online_client:/ {
      in_block = 1
      block_indent = indent
      print
      next
    }
    in_block && stripped != "" && indent <= block_indent {
      if (!found) {
        pad = sprintf("%*s", block_indent + 2, "")
        print pad "sharing: " val
      }
      in_block = 0
    }
    in_block && $0 ~ /^[[:space:]]*sharing:/ {
      sub(/sharing:.*/, "sharing: " val)
      found = 1
      print
      next
    }
    { print }
    END {
      if (in_block && !found) {
        pad = sprintf("%*s", block_indent + 2, "")
        print pad "sharing: " val
      }
    }
  ' "$CROWDSEC_CONFIG_FILE" > "$tmp"

  if nsh_cmp "$tmp" "$CROWDSEC_CONFIG_FILE"; then
    rm -f "$tmp"
    return 1
  fi

  local backup="${CROWDSEC_CONFIG_FILE}.bak"
  $SUDO cp -a "$CROWDSEC_CONFIG_FILE" "$backup"
  $SUDO cp "$tmp" "$CROWDSEC_CONFIG_FILE"
  rm -f "$tmp"
}


get_capi_pull_state()
{
  $SUDO test -e "$CROWDSEC_CONFIG_FILE" || return 1

  $SUDO awk '
    {
      match($0, /^[ ]*/)
      indent = RLENGTH
      stripped = $0
      gsub(/^[ ]*/, "", stripped)
    }
    /^[[:space:]]*online_client:/ { in_oc = 1; oc_indent = indent; next }
    in_pull && stripped != "" && indent <= pull_indent { in_pull = 0 }
    in_oc && stripped != "" && indent <= oc_indent { in_oc = 0 }
    in_oc && /^[[:space:]]*pull:/ { in_pull = 1; pull_indent = indent; next }
    in_pull && $0 ~ /^[[:space:]]*community:/ {
      v = $0; sub(".*community:[[:space:]]*", "", v); community = v; community_found = 1
    }
    in_pull && $0 ~ /^[[:space:]]*blocklists:/ {
      v = $0; sub(".*blocklists:[[:space:]]*", "", v); blocklists = v; blocklists_found = 1
    }
    END {
      if (!community_found) community = "true"
      if (!blocklists_found) blocklists = "true"
      print community "|" blocklists
    }
  ' "$CROWDSEC_CONFIG_FILE"
}


set_capi_pull()
{
  local value="$1"

  local tmp
  tmp=$(mktemp) || return 1

  $SUDO awk -v val="$value" '
    {
      match($0, /^[ ]*/)
      indent = RLENGTH
      stripped = $0
      gsub(/^[ ]*/, "", stripped)
    }
    /^[[:space:]]*online_client:/ { in_oc = 1; oc_indent = indent; print; next }

    in_pull && stripped != "" && indent <= pull_indent {
      pad2 = sprintf("%*s", pull_indent + 2, "")
      if (!found_community) print pad2 "community: " val
      if (!found_blocklists) print pad2 "blocklists: " val
      in_pull = 0
    }

    in_oc && stripped != "" && indent <= oc_indent {
      if (!found_pull) {
        pad1 = sprintf("%*s", oc_indent + 2, "")
        pad2 = sprintf("%*s", oc_indent + 4, "")
        print pad1 "pull:"
        print pad2 "community: " val
        print pad2 "blocklists: " val
      }
      in_oc = 0
    }

    in_oc && /^[[:space:]]*pull:/ { in_pull = 1; pull_indent = indent; found_pull = 1; print; next }

    in_pull && $0 ~ /^[[:space:]]*community:/ {
      sub(/community:.*/, "community: " val)
      found_community = 1
      print
      next
    }
    in_pull && $0 ~ /^[[:space:]]*blocklists:/ {
      sub(/blocklists:.*/, "blocklists: " val)
      found_blocklists = 1
      print
      next
    }
    { print }
    END {
      if (in_pull) {
        pad2 = sprintf("%*s", pull_indent + 2, "")
        if (!found_community) print pad2 "community: " val
        if (!found_blocklists) print pad2 "blocklists: " val
      } else if (in_oc && !found_pull) {
        pad1 = sprintf("%*s", oc_indent + 2, "")
        pad2 = sprintf("%*s", oc_indent + 4, "")
        print pad1 "pull:"
        print pad2 "community: " val
        print pad2 "blocklists: " val
      }
    }
  ' "$CROWDSEC_CONFIG_FILE" > "$tmp"

  if nsh_cmp "$tmp" "$CROWDSEC_CONFIG_FILE"; then
    rm -f "$tmp"
    return 1
  fi

  local backup="${CROWDSEC_CONFIG_FILE}.bak"
  $SUDO cp -a "$CROWDSEC_CONFIG_FILE" "$backup"
  $SUDO cp "$tmp" "$CROWDSEC_CONFIG_FILE"
  rm -f "$tmp"
}


show_or_set_capi_send()
{
  local action="$1"

  if ! $SUDO test -e "$CROWDSEC_CONFIG_FILE"; then
    log_err "${CROWDSEC_CONFIG_FILE} not found."
    return 1
  fi

  if [ -z "$action" ]; then
    case "$(get_capi_sharing)" in
      true) echo "Signal sharing: enabled" ;;
      false) echo "Signal sharing: disabled" ;;
      *) echo "Signal sharing: unknown" ;;
    esac
    return 0
  fi

  case "$action" in
    on|off) ;;
    *)
      log_err "Usage: crdsectl capi send [on|off]"
      return 1
      ;;
  esac

  require_root || return 1

  local new_val
  [ "$action" = "on" ] && new_val="true" || new_val="false"

  if ! set_capi_sharing "$new_val"; then
    echo "Signal sharing is already ${action}."
    return 0
  fi

  echo "Signal sharing turned ${action} (backup: ${CROWDSEC_CONFIG_FILE}.bak)."
  echo "Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


show_or_set_capi_pull()
{
  local action="$1"

  if ! $SUDO test -e "$CROWDSEC_CONFIG_FILE"; then
    log_err "${CROWDSEC_CONFIG_FILE} not found."
    return 1
  fi

  if [ -z "$action" ]; then
    local raw community blocklists
    raw=$(get_capi_pull_state)
    community="${raw%%|*}"
    blocklists="${raw##*|}"

    local c_label b_label
    [ "$community" = "true" ] && c_label="enabled" || c_label="disabled"
    [ "$blocklists" = "true" ] && b_label="enabled" || b_label="disabled"

    if [ "$c_label" = "$b_label" ]; then
      echo "Pulling blocklists: ${c_label}"
    else
      echo "Pulling blocklists: community ${c_label} / console blocklists ${b_label}"
    fi
    return 0
  fi

  case "$action" in
    on|off) ;;
    *)
      log_err "Usage: crdsectl capi pull [on|off]"
      return 1
      ;;
  esac

  require_root || return 1

  local new_val
  [ "$action" = "on" ] && new_val="true" || new_val="false"

  if ! set_capi_pull "$new_val"; then
    echo "Pulling blocklists is already ${action}."
    return 0
  fi

  echo "Pulling blocklists turned ${action} (backup: ${CROWDSEC_CONFIG_FILE}.bak)."
  echo "Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


# Our own placeholder file has no "login:" line; real credentials always do.
is_capi_registered()
{
  local capi_creds="/etc/crowdsec/online_api_credentials.yaml"
  $SUDO test -e "$capi_creds" && $SUDO grep -q "^login:" "$capi_creds" 2>/dev/null
}


capi_register()
{
  require_root || return 1

  if ! $SUDO test -e "$CROWDSEC_CONFIG_FILE"; then
    log_err "CrowdSec doesn't appear to be installed (${CROWDSEC_CONFIG_FILE} not found)."
    return 1
  fi

  if is_capi_registered; then
    echo "Already registered with Central API (CAPI)."
    return 0
  fi

  echo "Registering with CrowdSec's Central API (CAPI)..."

  if ! $SUDO cscli capi register; then
    log_err "CAPI registration failed."
    return 1
  fi

  # A manual opt-in should be a complete one, not require also running
  # "capi send on"/"capi pull on" separately afterward.
  set_capi_sharing true
  set_capi_pull true

  echo "Registered. Restarting ${CROWDSEC_SERVICE}..."
  $SUDO systemctl restart "$CROWDSEC_SERVICE"
}


capi_command()
{
  local sub="$1"
  local action="$2"

  case "$sub" in
    send)
      show_or_set_capi_send "$action"
      ;;
    pull)
      show_or_set_capi_pull "$action"
      ;;
    register)
      capi_register
      ;;
    *)
      log_err "Usage: crdsectl capi send|pull [on|off] | crdsectl capi register"
      return 1
      ;;
  esac
}


show_status()
{
  load_domino_config

  echo
  print_delim
  echo "CrowdSec Status"
  print_delim
  echo
  printf "%-24s :  %s\n" "crdsectl version" "$CRDSECTL_VERSION"
  printf "%-24s :  %s\n" "Config version" "$CRDSECTL_CONFIG_VERSION"
  echo

  detect_pkg_mgr
  printf "%-24s :  %s\n" "OS release" "$(os_pretty_name)"
  printf "%-24s :  %s\n" "Package manager" "${PKG_MGR:-unknown}"
  echo

  if have_command crowdsec; then
    local crowdsec_version
    crowdsec_version=$(crowdsec -version 2>/dev/null | head -1)
    printf "%-24s :  %s\n" "CrowdSec" "${crowdsec_version:-installed}"
  else
    printf "%-24s :  %s\n" "CrowdSec" "not installed"
  fi

  printf "%-24s :  %s / %s\n" \
    "CrowdSec service" \
    "$(service_state "$CROWDSEC_SERVICE")" \
    "$(enabled_state "$CROWDSEC_SERVICE")"

  printf "%-24s :  %s / %s\n" \
    "Firewall bouncer" \
    "$(service_state "$BOUNCER_SERVICE")" \
    "$(enabled_state "$BOUNCER_SERVICE")"

  echo

  printf "%-24s :  %s\n" "Default ban duration" "$(format_ban_duration || echo 'not set')"
  printf "%-24s :  %s\n" "Progressive ban" "$(format_progressive_state || echo 'unknown')"

  echo

  local creds_file="/etc/crowdsec/local_api_credentials.yaml"
  local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

  if $SUDO test -e "$creds_file"; then
    local lapi_url lapi_login
    lapi_url=$($SUDO awk -F': ' '/^url:/{print $2; exit}' "$creds_file")
    lapi_login=$($SUDO awk -F': ' '/^login:/{print $2; exit}' "$creds_file")
    printf "%-24s :  %s\n" "LAPI URL" "${lapi_url:-not set}"
    printf "%-24s :  %s\n" "LAPI login" "${lapi_login:-not set}"
  else
    printf "%-24s :  %s\n" "LAPI URL" "not configured"
  fi

  if $SUDO test -e "$bouncer_config"; then
    local bouncer_api_url
    bouncer_api_url=$($SUDO awk -F': ' '/^api_url:/{print $2; exit}' "$bouncer_config")
    printf "%-24s :  %s\n" "Bouncer API URL" "${bouncer_api_url:-not set}"
  fi

  echo
  echo "CrowdSec Central API:"

  # sharing/pull read from config.yaml directly rather than parsed from
  # "cscli capi status" text, and a live connection is only attempted
  # when something's actually enabled to check.
  if ! is_capi_registered; then
    printf "%-24s :  %s\n" "Connection" "disabled (not registered - run 'crdsectl capi register')"
  else
    local sharing pull_raw pull_community pull_blocklists
    sharing=$(get_capi_sharing)
    pull_raw=$(get_capi_pull_state)
    pull_community="${pull_raw%%|*}"
    pull_blocklists="${pull_raw##*|}"

    if [ "$sharing" = "true" ] || [ "$pull_community" = "true" ] || [ "$pull_blocklists" = "true" ]; then
      local capi_output
      capi_output=$($SUDO cscli capi status 2>&1)

      if echo "$capi_output" | grep -q "You can successfully interact with Central API"; then
        printf "%-24s :  %s\n" "Connection" "OK"
      elif echo "$capi_output" | grep -qiE "error|fail|unable|refused|timeout"; then
        printf "%-24s :  %s\n" "Connection" "FAILED"
      else
        printf "%-24s :  %s\n" "Connection" "unknown (unexpected cscli output)"
      fi
    else
      printf "%-24s :  %s\n" "Connection" "not attempted (sharing and pulling both disabled)"
    fi

    [ "$sharing" = "true" ] && printf "%-24s :  %s\n" "Signal sharing" "enabled" \
      || printf "%-24s :  %s\n" "Signal sharing" "disabled"
    [ "$pull_community" = "true" ] && printf "%-24s :  %s\n" "Community blocklist" "enabled" \
      || printf "%-24s :  %s\n" "Community blocklist" "disabled"
    [ "$pull_blocklists" = "true" ] && printf "%-24s :  %s\n" "Console blocklists" "enabled" \
      || printf "%-24s :  %s\n" "Console blocklists" "disabled"
  fi

  echo
  echo "Domino:"

  local configured_log
  configured_log=$(get_configured_output_log)
  local check_log

  if [ -z "$configured_log" ]; then
    printf "%-24s :  %s\n" "Output log" "not installed yet"
    check_log="$DOMINO_OUTPUT_LOG"
  elif [ "$configured_log" = "$DOMINO_OUTPUT_LOG" ]; then
    printf "%-24s :  %s\n" "Output log" "$configured_log"
    check_log="$configured_log"
  else
    printf "%-24s :  %s\n" "Output log" "${configured_log} (DOMINO_OUTPUT_LOG's current setting is ${DOMINO_OUTPUT_LOG} - run 'update' to apply)"
    check_log="$configured_log"
  fi

  if [ -r "$check_log" ]; then
    printf "%-24s :  %s\n" "Output log access" "OK"
  else
    printf "%-24s :  %s\n" "Output log access" "NOT READABLE"
  fi

  local acq_state parser_state scenario_state
  acq_state=$(file_state "$CRDSECTL_ACQUIS_FILE")
  parser_state=$(file_state "$CRDSECTL_PARSER_FILE")
  scenario_state=$(file_state "$CRDSECTL_SCENARIO_FILE")

  if [ "$acq_state" = "$parser_state" ] && [ "$parser_state" = "$scenario_state" ]; then
    printf "%-24s :  %s\n" "Domino config" "$acq_state"
  else
    printf "%-24s :  %s\n" "Domino config" "Acquisition ${acq_state}, Parser ${parser_state}, Scenario ${scenario_state}"
  fi

  echo

  if have_command cscli; then
    local decisions
    # "-o raw" is CSV with a header row (confirmed live 2026-08-24: "id,
    # source,ip,reason,..." always printed first) - counting raw lines
    # overcounted by one. Skip it before counting.
    decisions=$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | wc -l)
    printf "%-24s :  %s\n" "Active decisions" "$decisions"
  fi

  echo
}


test_crdsectl()
{
  load_domino_config

  echo
  print_delim
  echo "CrowdSec Test"
  print_delim
  echo

  local errors=0

  if ! have_command crowdsec; then
    printf "%-24s :  %s\n" "CrowdSec configuration" "NOT INSTALLED"
    errors=$((errors + 1))
  else
    if $SUDO crowdsec -t >/dev/null 2>&1; then
      printf "%-24s :  %s\n" "CrowdSec configuration" "OK"
    else
      printf "%-24s :  %s\n" "CrowdSec configuration" "FAILED"
      errors=$((errors + 1))
    fi
  fi

  if [ -r "$DOMINO_OUTPUT_LOG" ]; then
    printf "%-24s :  %s\n" "Output log" "OK"
  else
    printf "%-24s :  %s\n" "Output log" "NOT READABLE"
    errors=$((errors + 1))
  fi

  if [ -r "$CRDSECTL_ACQUIS_FILE" ]; then
    printf "%-24s :  %s\n" "Acquisition" "OK"
  else
    printf "%-24s :  %s\n" "Acquisition" "MISSING"
    errors=$((errors + 1))
  fi

  if [ -r "$CRDSECTL_PARSER_FILE" ]; then
    printf "%-24s :  %s\n" "Parser" "OK"
  else
    printf "%-24s :  %s\n" "Parser" "MISSING"
    errors=$((errors + 1))
  fi

  if [ -r "$CRDSECTL_SCENARIO_FILE" ]; then
    printf "%-24s :  %s\n" "Scenario" "OK"
  else
    printf "%-24s :  %s\n" "Scenario" "MISSING"
    errors=$((errors + 1))
  fi

  if systemctl is-active --quiet "$CROWDSEC_SERVICE" 2>/dev/null; then
    printf "%-24s :  %s\n" "CrowdSec service" "OK"
  else
    printf "%-24s :  %s\n" "CrowdSec service" "NOT RUNNING"
    errors=$((errors + 1))
  fi

  if systemctl is-active --quiet "$BOUNCER_SERVICE" 2>/dev/null; then
    printf "%-24s :  %s\n" "Firewall bouncer" "OK"
  else
    printf "%-24s :  %s\n" "Firewall bouncer" "NOT RUNNING"
    errors=$((errors + 1))
  fi

  echo

  if have_command cscli && [ -r "$CRDSECTL_PARSER_FILE" ]; then
    print_delim
    echo "Parser test"
    print_delim
    echo
    echo "Test log:"
    echo "$CRDSECTL_TEST_AUTH_LINE"
    echo

    # cscli explain exits 0 whether or not the line actually matched (verified
    # against this parser on 2026-08-21 - both a matching and a deliberately
    # non-matching line returned exit 0). The only reliable signal is the
    # explain trace itself, which creates evt.Meta.log_type and
    # evt.Parsed.source_ip only on a real match.
    local explain_output
    explain_output=$(cscli explain --type domino --log "$CRDSECTL_TEST_AUTH_LINE" --verbose 2>&1)
    echo "$explain_output"
    echo

    if echo "$explain_output" | grep -q "evt\.Meta\.log_type : domino_failed_auth" \
      && echo "$explain_output" | grep -q "evt\.Parsed\.source_ip : ${CRDSECTL_TEST_IP}"; then
      printf "%-24s :  %s\n" "Parser match" "OK"
    else
      printf "%-24s :  %s\n" "Parser match" "FAILED"
      errors=$((errors + 1))
    fi
  fi

  echo
  print_delim

  if [ "$errors" -eq 0 ]; then
    echo "CrowdSec test completed successfully."
    print_delim
    echo
    return 0
  fi

  echo "CrowdSec test completed with ${errors} error(s)."
  print_delim
  echo
  return 1
}


###############################################################################
# Operations
###############################################################################

show_alerts()
{
  cscli alerts list
}


show_decisions()
{
  cscli decisions list
}


show_metrics()
{
  cscli metrics
}


show_collections()
{
  cscli collections list
}


enroll_console()
{
  local token="$1"

  if [ -z "$token" ]; then
    log_err "No enrollment token specified."
    return 1
  fi

  require_root || return 1

  $SUDO cscli console enroll "$token" || return 1

  echo
  echo "Reloading CrowdSec..."
  $SUDO systemctl reload "$CROWDSEC_SERVICE"
}


install_trusted_root()
{
  local ca_cert_source="$1"

  if [ -z "$ca_cert_source" ]; then
    return 0
  fi

  if [ ! -r "$ca_cert_source" ]; then
    log_err "Cannot find specified trusted root: ${ca_cert_source}"
    return 1
  fi

  if ! have_command openssl; then
    pkg_install openssl || return 1
  fi

  echo
  print_delim
  echo "Root Certificate Information"
  print_delim
  openssl x509 -in "$ca_cert_source" -text -noout

  echo
  print_delim
  echo "Updating system trust store"
  print_delim
  echo

  case "$PKG_MGR" in
    apt)
      pkg_install ca-certificates || return 1
      $SUDO cp -f "$ca_cert_source" /usr/local/share/ca-certificates/crdsectl-hub-ca.crt || return 1
      $SUDO update-ca-certificates || return 1
      ;;

    dnf|yum)
      $SUDO cp -f "$ca_cert_source" /etc/pki/ca-trust/source/anchors/crdsectl-hub-ca.crt || return 1
      $SUDO update-ca-trust || return 1
      ;;

    *)
      log_err "Unknown package manager: '$PKG_MGR' - don't know how to update the OS trust store."
      return 1
      ;;
  esac

  echo
}


trust_root()
{
  local ca_cert_source="$1"

  if [ -z "$ca_cert_source" ]; then
    log_err "Usage: crdsectl trust <ca-cert-path>"
    return 1
  fi

  require_root || return 1

  if ! detect_pkg_mgr; then
    log_err "Version ${CRDSECTL_VERSION} currently supports Debian/Ubuntu (apt) and RHEL/Fedora (dnf/yum) installations only."
    return 1
  fi

  install_trusted_root "$ca_cert_source"
}


# Pre-flight check for register_lapi(): tries an actual connection to the
# hub before touching any config, so a bad URL or an untrusted TLS cert
# fails fast with a clear message here - instead of succeeding at writing
# config, restarting crowdsec, and only then failing deep in
# "journalctl -xeu crowdsec" with a cryptic
# "x509: certificate signed by unknown authority" once it tries to log in.
# curl (not crowdsec/cscli) does both checks in one shot: exit code 60
# specifically means the TLS certificate didn't validate (distinct from a
# plain connection failure), which is exactly the "forgot to run
# 'crdsectl trust' first" case.
check_hub_reachable()
{
  local hub_url="$1"

  if ! have_command curl; then
    log_err "curl command not found - cannot verify hub connectivity before registering."
    return 1
  fi

  local curl_err
  curl_err=$(curl --silent --show-error --max-time 10 -o /dev/null "$hub_url" 2>&1)
  local rc=$?

  if [ $rc -eq 0 ]; then
    return 0
  fi

  if [ $rc -eq 60 ]; then
    log_err "TLS certificate for ${hub_url} could not be verified (curl: ${curl_err}). If the hub uses a self-signed/private CA, run 'crdsectl trust <ca-cert-path>' first, then retry register."
    return 1
  fi

  log_err "Cannot reach ${hub_url} (curl: ${curl_err}). Check the URL, that the hub is up, and network connectivity/NETWORK_MODE before retrying."
  return 1
}


# Points this agent at a self-hosted crdsec-hub (see
# ../crdsec-hub), instead of running fully standalone. Needs two
# separate credentials from two separate hub registrations, because
# crowdsec and crowdsec-firewall-bouncer are two separate processes on
# this server, each independently authenticating to the hub for a
# different one-way operation:
#
#   machine_login / machine_password (from crdsec-hub.sh addmachine)
#     Used by THIS AGENT'S OWN crowdsec process (via
#     /etc/crowdsec/local_api_credentials.yaml) to POST alerts it detects
#     locally (e.g. a detected brute-force) to the hub. Write-only: lets
#     this server report in, nothing more.
#
#   bouncer_key (from crdsec-hub.sh addbouncer)
#     Used by THIS AGENT'S OWN crowdsec-firewall-bouncer process (a
#     separate config file, a separate credential) to POLL the hub for
#     the current decision list and turn it into local nftables rules.
#     Read-only: lets this server enforce bans, nothing more.
#
# Keeping them separate limits blast radius if one leaks: the bouncer key
# alone can't be used to submit fake alerts, and the machine password
# alone can't be used to just read the ban list.

# Checks whether a CrowdSec "<file>.local" overlay exists and sets any of
# the given credential-relevant keys (an "^(a|b|c)"-shaped grep -E
# pattern) - these silently override the real config file's values with
# no error anywhere if left stale, which is exactly what happened live in
# production (see the comment at the call site). Without force, just
# warns and lists what it found; with force, backs the .local file up and
# strips the matching lines so the real config file's values actually win.
check_local_override()
{
  local local_file="$1"
  local key_pattern="$2"
  local force="$3"

  $SUDO test -e "$local_file" || return 0

  local matches
  matches=$($SUDO grep -E "^(${key_pattern})" "$local_file" 2>/dev/null)

  [ -z "$matches" ] && return 0

  echo
  echo "Warning: ${local_file} exists and sets these values - they silently"
  echo "override what was just written above, with no error if they're wrong:"
  echo "$matches" | sed 's/^/  /'

  if [ "$force" = "yes" ]; then
    local backup
    backup=$(mktemp)
    $SUDO cp -a "$local_file" "$backup"
    $SUDO sed -i -E "/^(${key_pattern})/d" "$local_file"
    echo "--force: removed the lines above from ${local_file} (backup: ${backup})."
  else
    echo "Re-run with --force to remove them automatically, or edit ${local_file} by hand."
  fi
}


register_lapi()
{
  local hub_url="$1"
  local machine_login="$2"
  local machine_password="$3"
  local bouncer_key="$4"

  # Checked before "shift 4" deliberately: "shift 4" is a no-op (silently,
  # since bash errors "shift count out of range" rather than shifting
  # partially) when fewer than 4 args were actually given - confirmed live
  # (2026-08-22) that skipping this check first left $1 still holding the
  # URL, which the --force-parsing loop below then misread as an unknown
  # option ("Unknown option: 'https://...'") instead of this usage message.
  if [ -z "$hub_url" ] || [ -z "$machine_login" ] || [ -z "$machine_password" ] || [ -z "$bouncer_key" ]; then
    log_err "Usage: crdsectl register <url> <machine-login> <machine-password> <bouncer-key> [--force]"
    return 1
  fi

  shift 4

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

  # Normalize once so the two files below don't end up with inconsistent
  # trailing slashes depending on how the caller typed the URL.
  hub_url="${hub_url%/}"

  require_root || return 1

  if ! have_command crowdsec; then
    log_err "CrowdSec is not installed."
    return 1
  fi

  local creds_file="/etc/crowdsec/local_api_credentials.yaml"
  local bouncer_config="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"

  if ! $SUDO test -e "$bouncer_config"; then
    log_err "Bouncer config not found at ${bouncer_config}. Is the firewall bouncer installed?"
    return 1
  fi

  check_hub_reachable "$hub_url" || return 1

  local tmpdir
  tmpdir=$(mktemp -d) || return 1

  local creds_tmp="${tmpdir}/local_api_credentials.yaml"
  local bouncer_tmp="${tmpdir}/crowdsec-firewall-bouncer.yaml"

  # Machine credentials: point this agent's own LAPI client at the hub
  # instead of its default local one. This deliberately leaves this
  # instance's own local LAPI server (api.server.enable in config.yaml)
  # running as-is - on a real deployment, agent and hub are separate
  # machines with independent 127.0.0.1s, so the agent's own unused local
  # LAPI is genuinely harmless there. It only becomes a real port conflict
  # (127.0.0.1:8080 bind failure) when agent and hub are deliberately
  # co-located on one machine for testing with the agent on
  # --network host - that's a test-topology choice to solve via
  # ../crdsectl/run-install-test-container.sh's NETWORK_MODE (e.g. "bridge" instead of "host"),
  # not something register should change about the agent's own config.
  cat > "$creds_tmp" <<EOF
url: ${hub_url}
login: ${machine_login}
password: ${machine_password}
EOF

  # Bouncer: a separate config file and a separate credential (an API key,
  # not the machine login/password above), pointed at the same hub.
  $SUDO cat "$bouncer_config" > "$bouncer_tmp" || {
    rm -rf "$tmpdir"
    return 1
  }

  sed -i \
    -e "s#^api_url:.*#api_url: ${hub_url}/#" \
    -e "s#^api_key:.*#api_key: ${bouncer_key}#" \
    "$bouncer_tmp"

  local backup_dir="${tmpdir}/backup"
  mkdir -p "$backup_dir"

  local creds_existed="no"
  make_backup "$creds_file" "${backup_dir}/local_api_credentials.yaml"
  [ $? -eq 0 ] && creds_existed="yes"

  make_backup "$bouncer_config" "${backup_dir}/crowdsec-firewall-bouncer.yaml"

  install_generated_file "$creds_tmp" "$creds_file" 0600
  local rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    rm -rf "$tmpdir"
    return 1
  fi

  install_generated_file "$bouncer_tmp" "$bouncer_config" 0600
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    restore_file "$creds_file" "${backup_dir}/local_api_credentials.yaml" "$creds_existed"
    rm -rf "$tmpdir"
    return 1
  fi

  # CrowdSec layers an optional "<file>.local" on top of the real config
  # file, for local customization that survives a package upgrade. A
  # credential field left over in one of these silently overrides whatever
  # register just wrote above, with no error anywhere - found live in
  # production (2026-08-22): a stale api_key in
  # crowdsec-firewall-bouncer.yaml.local (from a CrowdSec install that
  # pre-dated crdsectl on that machine) caused every re-registration to
  # keep failing with "access forbidden", even though the real config file
  # and the freshly-issued key were both correct - untraceable without
  # reading the .local file directly, since nothing in the logs points at
  # it. Surfaced here unconditionally (not just under --force) so this
  # can't silently recur.
  check_local_override "${creds_file}.local" "url:|login:|password:" "$force"
  check_local_override "${bouncer_config}.local" "api_url:|api_key:" "$force"

  echo
  echo "Validating CrowdSec configuration..."

  if ! $SUDO crowdsec -t; then
    echo
    log_err "CrowdSec configuration validation failed. Restoring previous configuration."

    restore_file "$creds_file" "${backup_dir}/local_api_credentials.yaml" "$creds_existed"
    restore_file "$bouncer_config" "${backup_dir}/crowdsec-firewall-bouncer.yaml" "yes"

    rm -rf "$tmpdir"
    return 1
  fi

  rm -rf "$tmpdir"

  $SUDO systemctl restart "$CROWDSEC_SERVICE" || return 1
  $SUDO systemctl restart "$BOUNCER_SERVICE" || return 1

  echo
  echo "This agent now reports its own decisions to, and consumes decisions"
  echo "from: ${hub_url}"
  echo
  echo "Its own local LAPI is still running but unused (nothing points at"
  echo "it anymore). On a real deployment with agent and hub on separate"
  echo "machines that's harmless; if you're testing both co-located on one"
  echo "machine with --network host, use NETWORK_MODE=bridge instead to"
  echo "avoid a port conflict on 127.0.0.1:8080."
}


block_ip()
{
  local ip="$1"
  local duration="$2"

  if [ -z "$ip" ]; then
    log_err "No IP address specified."
    return 1
  fi

  require_root || return 1

  if [ -n "$duration" ]; then
    $SUDO cscli decisions add --ip "$ip" --duration "$duration"
  else
    $SUDO cscli decisions add --ip "$ip"
  fi
}


unblock_ip()
{
  local ip="$1"

  if [ -z "$ip" ]; then
    log_err "No IP address specified."
    return 1
  fi

  require_root || return 1
  $SUDO cscli decisions delete --ip "$ip"
}


test_block()
{
  local ip="${1:-1.2.3.4}"
  local duration="${2:-10m}"
  local wait_secs=12

  require_root || return 1

  if ! have_command nft; then
    log_err "nft command not found."
    return 1
  fi

  echo
  print_delim
  echo "CrowdSec Block Test"
  print_delim
  echo
  echo "This is a manual admin test: it adds a real CrowdSec decision for a"
  echo "test IP and checks whether the firewall bouncer actually syncs it into"
  echo "the live nftables ruleset - i.e. whether decision -> enforcement works"
  echo "end to end. It does not touch the output log or the parser/"
  echo "scenario pipeline (that's what \"crdsectl test\" already covers)."
  echo
  echo "Adding decision: ${ip} (duration ${duration})"
  echo

  block_ip "$ip" "$duration" || return 1

  local waited=0
  local synced=0
  local decision_confirmed=0

  if in_container; then
    echo
    echo "Skipping the nftables wait - sync often can't be verified inside a"
    echo "container anyway (restricted netfilter/kernel access, even"
    echo "--privileged - WSL2 in particular). Checking that the decision"
    echo "itself was actually created instead:"

    if $SUDO cscli decisions list -o raw 2>/dev/null | grep -q "$ip"; then
      decision_confirmed=1
    fi
  else
    echo
    echo "Checking nftables for sync (up to ${wait_secs}s)..."

    while [ "$waited" -lt "$wait_secs" ]; do
      if $SUDO nft list ruleset | grep -q "$ip"; then
        synced=1
        break
      fi

      sleep 1
      waited=$((waited + 1))
    done
  fi

  echo

  if [ "$synced" -eq 1 ]; then
    printf "%-24s :  %s\n" "Firewall block" "OK"
  elif in_container; then
    if [ "$decision_confirmed" -eq 1 ]; then
      printf "%-24s :  %s\n" "Decision" "OK"
      printf "%-24s :  %s\n" "Firewall block" "NOT VERIFIED (container)"
      echo
      echo "The decision was confirmed in \"cscli decisions list\" - that layer"
      echo "works. Nftables enforcement itself couldn't be verified because"
      echo "this is running inside a container, where sync often can't happen"
      echo "even with --privileged (restricted netfilter/kernel access - WSL2"
      echo "in particular). Not necessarily a crdsectl or bouncer problem - on"
      echo "a real (non-containerized) Domino server this should sync normally."
    else
      printf "%-24s :  %s\n" "Firewall block" "FAILED"
      echo
      echo "${ip} was not found in \"cscli decisions list\" either - this is a"
      echo "real failure, not just the container's nftables limitation. Check:"
      echo "  systemctl status ${CROWDSEC_SERVICE}"
      echo "  journalctl -u ${CROWDSEC_SERVICE} --no-pager -n 50"
    fi
  else
    printf "%-24s :  %s\n" "Firewall block" "FAILED"
    echo

    local reversed_ip=""
    case "$ip" in
      *.*.*.*)
        reversed_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
        ;;
    esac

    if [ -n "$reversed_ip" ] && $SUDO nft list ruleset | grep -q "$reversed_ip"; then
      echo "${ip} wasn't found, but ${reversed_ip} (its octets reversed) was."
      echo "The decision itself is correct (check with \"crdsectl decisions\")."
      echo "This is a known bug in the plain \"crowdsec-firewall-bouncer\""
      echo "package (v0.0.25) - \"crdsectl install\" always installs the"
      echo "dedicated \"crowdsec-firewall-bouncer-nftables\" package instead"
      echo "(v0.0.36, unaffected), so re-running it should resolve this. If"
      echo "it doesn't, this needs reporting upstream to CrowdSec."
    else
      echo "${ip} was not found in the nftables ruleset. Check:"
      echo "  systemctl status ${BOUNCER_SERVICE}"
      echo "  journalctl -u ${BOUNCER_SERVICE} --no-pager -n 50"
    fi
  fi

  echo
  echo "This test does not clean up after itself."
  echo
  echo "To inspect the decision:"
  echo "  crdsectl decisions"
  echo
  echo "To remove it:"
  echo "  crdsectl unblock ${ip}"
  echo
  echo "(It also expires automatically after ${duration}.)"
  echo
}


# Real end-to-end test: unlike "test" (a cscli-explain dry run, nothing
# written anywhere) and "blocktest" (injects a decision directly via cscli,
# bypassing log acquisition/parsing entirely), this appends real synthetic
# auth-failure lines into the actual live output log - the same file the
# acquisition config tails - and waits to see whether CrowdSec genuinely
# detects, parses, and scores them on its own. Writes more than the
# scenario's leaky-bucket capacity (5) so it actually overflows into a
# decision, not just accumulates below the threshold.
test_log()
{
  local ip="${1:-$CRDSECTL_TEST_IP}"
  local count=7
  local wait_secs=20

  load_domino_config
  require_root || return 1

  if [ ! -e "$DOMINO_OUTPUT_LOG" ]; then
    log_err "Output log not found: ${DOMINO_OUTPUT_LOG}"
    return 1
  fi

  echo
  print_delim
  echo "CrowdSec Log Test"
  print_delim
  echo
  echo "This appends ${count} synthetic auth-failure lines for ${ip} directly"
  echo "into the live output log (${DOMINO_OUTPUT_LOG}) - the real file"
  echo "crdsectl's acquisition tails - then waits to see whether CrowdSec"
  echo "genuinely detects, parses, and scores them on its own: log"
  echo "acquisition -> parser -> scenario -> decision -> bouncer -> nftables,"
  echo "nothing injected or bypassed."
  echo
  echo "This PERMANENTLY appends ${count} lines to the real log file - unlike"
  echo "the decision it may create (removable with \"unblock\"), the log"
  echo "lines themselves cannot be undone by this command."
  echo

  local i line
  for i in $(seq 1 "$count"); do
    line="$(date '+%m/%d/%Y %I:%M:%S %p')  http: user [${ip}] authentication failure using internet password"
    echo "$line" | $SUDO tee -a "$DOMINO_OUTPUT_LOG" >/dev/null || return 1
  done

  echo "Wrote ${count} lines. Waiting for CrowdSec to parse/score them (up to ${wait_secs}s)..."

  local waited=0
  local detected=0

  while [ "$waited" -lt "$wait_secs" ]; do
    if $SUDO cscli decisions list -o raw 2>/dev/null | grep -q "$ip"; then
      detected=1
      break
    fi

    sleep 1
    waited=$((waited + 1))
  done

  echo

  if [ "$detected" -eq 1 ]; then
    printf "%-24s :  %s\n" "Log -> decision pipeline" "OK"
  else
    printf "%-24s :  %s\n" "Log -> decision pipeline" "FAILED"
    echo
    echo "No decision appeared for ${ip}. Check:"
    echo "  crdsectl log 50"
    echo "  cscli metrics"
    echo "  cscli explain --type domino --log \"\$line\" --verbose"
  fi

  echo
  echo "To inspect: crdsectl decisions"
  echo "To remove the decision (if any): crdsectl unblock ${ip}"
  echo "(The ${count} log lines already written remain in ${DOMINO_OUTPUT_LOG}.)"
  echo
}


show_firewall()
{
  require_root || return 1

  if ! have_command nft; then
    log_err "nft command not found."
    return 1
  fi

  $SUDO nft list ruleset | grep -i -A20 -B2 crowdsec
}


show_log()
{
  local lines="${1:-100}"

  case "$lines" in
    ''|*[!0-9]*)
      log_err "Log line count must be numeric."
      return 1
      ;;
  esac

  require_root || return 1
  $SUDO journalctl -u "$CROWDSEC_SERVICE" -n "$lines" --no-pager
}


reload_crowdsec()
{
  require_root || return 1

  if ! $SUDO crowdsec -t; then
    log_err "CrowdSec configuration validation failed. Not reloading."
    return 1
  fi

  $SUDO systemctl reload "$CROWDSEC_SERVICE"
}


restart_crowdsec()
{
  require_root || return 1

  if ! $SUDO crowdsec -t; then
    log_err "CrowdSec configuration validation failed. Not restarting."
    return 1
  fi

  $SUDO systemctl restart "$CROWDSEC_SERVICE"
  $SUDO systemctl restart "$BOUNCER_SERVICE"
}


systemd_command()
{
  local command="$1"

  require_root || return 1

  if [ -z "$command" ]; then
    systemctl status "$CROWDSEC_SERVICE"
    echo
    systemctl status "$BOUNCER_SERVICE"
    return
  fi

  case "$command" in
    start|stop|restart|enable|disable)
      $SUDO systemctl "$command" "$CROWDSEC_SERVICE"
      $SUDO systemctl "$command" "$BOUNCER_SERVICE"
      ;;
    status)
      systemctl status "$CROWDSEC_SERVICE"
      echo
      systemctl status "$BOUNCER_SERVICE"
      ;;
    *)
      log_err "Unknown systemd option: $command"
      return 1
      ;;
  esac
}


show_config()
{
  load_domino_config

  echo
  print_delim
  echo "CrowdSec Configuration"
  print_delim
  echo
  if [ -r "$DOMINO_CONFIG_FILE" ]; then
    printf "%-24s :  %s\n" "Service configuration" "$DOMINO_CONFIG_FILE (found)"
  else
    printf "%-24s :  %s\n" "Service configuration" "$DOMINO_CONFIG_FILE (not found - using default/override values)"
  fi
  echo
  echo "Domino:"
  printf "%-24s :  %s\n" "Output log" "$DOMINO_OUTPUT_LOG"
  printf "%-24s :  %s\n" "Acquisition" "$CRDSECTL_ACQUIS_FILE"
  printf "%-24s :  %s\n" "Parser" "$CRDSECTL_PARSER_FILE"
  printf "%-24s :  %s\n" "Scenario" "$CRDSECTL_SCENARIO_FILE"
  echo
  printf "%-24s :  %s\n" "crdsectl command" "$CRDSECTL_INSTALL_PATH"
  echo
}


show_version()
{
  echo "crdsectl $CRDSECTL_VERSION"
  echo "CrowdSec configuration $CRDSECTL_CONFIG_VERSION"

  if have_command crowdsec; then
    crowdsec -version 2>/dev/null | head -1
  fi
}


show_help()
{
  echo
  echo "crdsectl"
  echo "--------"
  echo
  echo "Syntax: crdsectl [command]"
  echo
  printf "  %-37s%s\n" "-" "Show CrowdSec status"
  printf "  %-37s%s\n" "help" "Show this help"
  printf "  %-37s%s\n" "install [log-file] [token]" "Install CrowdSec, bouncer, service config, optional console enroll"
  printf "  %-37s%s\n" "update [log-file]" "Update embedded CrowdSec configuration"
  printf "  %-37s%s\n" "upgrade" "Update the crdsectl script itself (from GitHub, or run a newer local file directly)"
  printf "  %-37s%s\n" "test" "Test configuration and parser"
  printf "  %-37s%s\n" "status" "Show CrowdSec status"
  printf "  %-37s%s\n" "alerts (a)" "List CrowdSec alerts"
  printf "  %-37s%s\n" "decisions (d)" "List active CrowdSec decisions"
  printf "  %-37s%s\n" "metrics" "Show CrowdSec metrics"
  printf "  %-37s%s\n" "collections" "List installed CrowdSec collections"
  printf "  %-37s%s\n" "enroll <token>" "Enroll this instance with the CrowdSec console"
  printf "  %-37s%s\n" "trust <ca-cert-path>" "Trust a self-hosted hub's CA (run before register, if needed)"
  printf "  %-37s%s\n" "register <url> <login> <pw> <key>" "Report to / consume decisions from a self-hosted hub (add --force to overwrite)"
  printf "  %-37s%s\n" "block <IP> [duration]" "Add a CrowdSec decision"
  printf "  %-37s%s\n" "unblock <IP>" "Delete CrowdSec decisions for an IP"
  printf "  %-37s%s\n" "blocktest [IP] [duration]" "Block a test IP and verify nftables (default 1.2.3.4, 10m)"
  printf "  %-37s%s\n" "logtest [IP]" "Write real test log lines and verify the full log->decision pipeline"
  printf "  %-37s%s\n" "duration [value]" "Show or set the default ban duration (e.g. 4h)"
  printf "  %-37s%s\n" "progressive [on|off]" "Show or set progressive (escalating) ban duration"
  printf "  %-37s%s\n" "profile" "Open profiles.yaml in \$EDITOR (or vi), validate, and restart"
  printf "  %-37s%s\n" "capi send|pull [on|off]" "Show or set CAPI signal sharing / blocklist pulling"
  printf "  %-37s%s\n" "capi register" "Opt in to CrowdSec's Central API (off by default)"
  printf "  %-37s%s\n" "firewall (nft)" "Show CrowdSec nftables rules"
  printf "  %-37s%s\n" "log [lines]" "Show CrowdSec journal (default: 100 lines)"
  printf "  %-37s%s\n" "reload" "Validate and reload CrowdSec"
  printf "  %-37s%s\n" "restart" "Validate and restart CrowdSec and bouncer"
  printf "  %-37s%s\n" "systemd [cmd]" "Manage CrowdSec and bouncer services"
  printf "  %-37s%s\n" "config" "Show CrowdSec configuration"
  printf "  %-37s%s\n" "version" "Show version information"
  echo
  echo "Remote install:"
  echo "  export CRDSECTL_URL=https://raw.githubusercontent.com/nashcom/crowdsec-tools/main/crdsectl/crdsectl.sh; curl -fsSL \"\$CRDSECTL_URL\" | bash -"
  echo
}


###############################################################################
# Main
###############################################################################

main()
{
  load_domino_config
  setup_sudo >/dev/null 2>&1 || true

  case "$1" in
    "")
      # CRDSECTL_URL alone is not enough to trigger an install: once exported,
      # it stays in the shell's environment for later commands too (a child
      # process can never unset a variable in its parent shell). Requiring
      # stdin to also not be a terminal means this only fires for an actual
      # "curl ... | bash -" pipe, not a later interactive "crdsectl" call that
      # merely inherits a lingering CRDSECTL_URL.
      if [ -n "$CRDSECTL_URL" ] && [ ! -t 0 ]; then
        echo "Detected CRDSECTL_URL (${CRDSECTL_URL}) with no terminal on stdin - running install."
        install_crowdsec
      else
        show_status
      fi
      ;;

    help|-h|--help)
      show_help
      ;;

    install)
      install_crowdsec "$2" "$3"
      ;;

    update)
      update_domino_config "$2"
      local rc=$?

      if [ $rc -eq 2 ]; then
        echo
        echo "Reloading CrowdSec..."
        $SUDO systemctl reload "$CROWDSEC_SERVICE"
        return $?
      fi

      return $rc
      ;;

    upgrade)
      upgrade_self
      ;;

    test)
      test_crdsectl
      ;;

    status)
      show_status
      ;;

    alerts|a)
      show_alerts
      ;;

    decisions|d)
      show_decisions
      ;;

    metrics)
      show_metrics
      ;;

    collections)
      show_collections
      ;;

    enroll)
      enroll_console "$2"
      ;;

    trust)
      trust_root "$2"
      ;;

    register)
      shift
      register_lapi "$@"
      ;;

    block)
      block_ip "$2" "$3"
      ;;

    unblock)
      unblock_ip "$2"
      ;;

    blocktest)
      test_block "$2" "$3"
      ;;

    logtest)
      test_log "$2"
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

    capi)
      capi_command "$2" "$3"
      ;;

    firewall|nft)
      show_firewall
      ;;

    log)
      show_log "$2"
      ;;

    reload)
      reload_crowdsec
      ;;

    restart)
      restart_crowdsec
      ;;

    systemd)
      systemd_command "$2"
      ;;

    config|cfg)
      show_config
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

