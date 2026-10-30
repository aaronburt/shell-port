#!/bin/sh
set -e
if [ ! -f /hostkeys/ssh_host_ed25519_key ]; then
  ssh-keygen -q -t ed25519 -N "" -f /hostkeys/ssh_host_ed25519_key
fi
exec /usr/sbin/sshd -D -e
