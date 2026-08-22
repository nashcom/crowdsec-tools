# ---------------------------------------------------------------------------
# Ubuntu + systemd test image for crdsectl
#
# The official ubuntu image ships without systemd, so systemctl-dependent
# code (crdsectl.sh install/status/reload/restart/systemd/log) has nothing to
# talk to. This installs systemd and boots it as PID 1 via ENTRYPOINT, the
# same role registry.access.redhat.com/ubi10-init plays for the RHEL path.
# ---------------------------------------------------------------------------

FROM ubuntu:latest

# Note: intentionally not clearing /var/lib/apt/lists afterward. This is a
# dev/test container, not a slim production image - crdsectl.sh and the
# CrowdSec installer both run further apt-get installs at runtime and need
# a live package index.
RUN apt-get update \
  && apt-get install -y --no-install-recommends systemd systemd-sysv dbus vim-tiny curl ca-certificates git net-tools dnsutils \
  && apt-get clean

ENTRYPOINT ["/sbin/init"]
