#!/bin/sh
# Sample QNX startup script with deliberately planted flaws. DO NOT SHIP.
on -t /dev/ser1 sh
inetd -f /etc/inetd.conf &  # telnetd ftpd enabled in inetd.conf
chmod 777 /data/config
umask 000
io-pkt-v6-hc -d e1000 &
