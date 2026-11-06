#!/bin/sh
# Clean sample startup script: no shells, no cleartext services.
umask 022
chmod 755 /data/config
io-pkt-v6-hc -d e1000 &
# Adaptive partitioning: safety partition guaranteed budget (aps)
sched_aps -c safety=30,system=70
