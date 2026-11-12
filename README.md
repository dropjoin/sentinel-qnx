# Sentinel for QNX

A host-based deterministic security auditor for QNX 8.0 system images.

Sentinel reads the files that define a QNX target image (buildfiles,
startup scripts, image manifests, sshd_config, passwd/shadow) and
flags production-unsafe configuration before the image ever ships:

- Interactive debug shells spawned on serial or virtual consoles
- Cleartext remote services (telnet/FTP via inetd)
- World-writable permissions set in startup scripts, and files shipped
  world-writable by buildfile perms attributes
- Bundled components with known vulnerability classes (OpenSSL 1.0.x
  and 1.1.0, old BusyBox/Dropbear/zlib)
- Unsafe sshd_config settings (root login, password auth, empty
  passwords, protocol 1, X11 forwarding) and unsafe accounts (empty
  password fields, extra uid-0 accounts)
- Missing adaptive partitioning (APS) configuration, so safety-critical
  threads have no guaranteed CPU budget

Every finding reports severity, exact file and line (set-level
findings name the image set instead), a plain-English explanation of
why it matters on an embedded target, and a suggested patch the
developer can apply or reject. The audit core is deterministic and
fully reproducible offline: authored explanations describe each
finding's impact in context, and `sentinel fix` applies the
mechanically safe repairs (shell/inetd lines disabled, permissions
tightened) while leaving component upgrades, account changes and APS
design as human decisions.

Category: Developer Tooling & Host Tools (host-based analysis tooling
for QNX 8.0 software, explicitly in scope for the QNX Global Hackathon).

## Quick start

```bash
python3 -m sentinel.cli audit samples/flawed-startup.sh samples/flawed-manifest.txt
# exits 1 and prints findings; the clean samples audit quiet:
python3 -m sentinel.cli audit samples/clean-startup.sh samples/clean-manifest.txt
```

## Build and run instructions

- Host tool: Python 3.10+, no third-party dependencies for the audit core.
- Run the tests: `PYTHONPATH=. python3 -m pytest tests/` (or any test
  runner; the suite is plain asserts).
- QNX side: Sentinel targets images built with **QNX SDP 8.0**
  (QNX Everywhere). The automated demo flow audits a sample image
  definition, applies the suggested fixes, and re-audits clean
  (`sh demo/run_demo.sh`); it does not depend on QEMU. Booting the
  hardened image on the **QEMU** target (`mkqnximage --run` from the
  QNX SDP 8.0 Quick Start image) is a separate manual validation
  step, not part of the demo script.
- Toolchain: QNX SDP 8.0 host tools on Linux; the auditor itself runs
  anywhere Python 3.10+ runs.

## Status

v0.1.0: deterministic rule engine (13 checks across 8 rule families),
CLI, planted-flaw and clean sample sets, test suite green. In
development for the QNX Global Hackathon (submission period Nov 2 -
Dec 15, 2026).

## License

MIT, see LICENSE.
