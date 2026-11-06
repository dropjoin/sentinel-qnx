# How Sentinel uses QNX-specific technologies

Sentinel is a host tool, but everything it audits is QNX-specific:

- **mkifs buildfiles**: the parser understands buildfile attribute
  blocks (perms, uid, gid) and file mappings, which is how a QNX
  image's shipped permissions are actually decided.
- **Startup scripts and procnto boot flow**: shell-spawn, inetd and
  permission checks target the scripts that run under procnto at boot.
- **Adaptive partitioning (APS)**: the set-level check verifies a
  scheduler partitioning configuration exists, because guaranteed CPU
  budgets for safety partitions are a QNX-native safety mechanism with
  no direct equivalent in a generic Linux audit.
- **Resource managers and io-pkt**: cleartext-service and networking
  findings are phrased for QNX's resource-manager architecture rather
  than generic Unix daemons.
- **QEMU target validation**: the demo flow boots the audited image
  definition on the QNX SDP 8.0 Quick Start QEMU image, closing the
  loop from static audit to a running QNX system.

Roadmap: parse the compiled image's filesystem manifest directly,
cross-check running-system state over a QNX target agent (qconn), and
score images against APS budgets measured at runtime.
