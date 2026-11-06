# Demo video plan (must stay under 3:00 for the QNX submission)

- 0:00-0:20 Hook: a QNX image with a root shell on the serial console
  ships to production. One cable is full device control. Sentinel exists
  to catch that before it ships.
- 0:20-1:00 Run demo step 1+2: audit the planted-flaw sample set, show
  the findings list and the narrative report (severity, file:line,
  impact scenario, fix).
- 1:00-1:40 Run demo step 3: sentinel fix, 8 findings -> 3 remaining,
  and the 3 remaining are honestly labelled human decisions (component
  upgrades, APS design).
- 1:40-2:20 Clean set audits quiet; show the sshd_config and buildfile
  rules firing on their samples.
- 2:20-2:50 QEMU segment (once SDP access lands): boot the QNX 8.0
  Quick Start image, show the hardened startup running live.
- 2:50-3:00 Close: repo, MIT license, category Developer Tooling &
  Host Tools.

Title and description are delivered with the video file, per standing
practice. The user uploads the video himself.
