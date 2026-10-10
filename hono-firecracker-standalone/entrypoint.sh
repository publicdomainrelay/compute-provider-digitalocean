#!/bin/sh
set -e
# The guest's launcher must not run as root: pasta, started as root, drops the
# process that starts the VMM to nobody, and a process running as nobody cannot
# write the guest's own record. Started as an ordinary user it does its own user
# mapping and keeps the files and devices it already had.
#
# The devices arrive owned by root with the container's kvm group, so they are
# opened up here and then the launcher runs as the unprivileged user.
[ -e /dev/kvm ] && chmod 666 /dev/kvm 2>/dev/null || true
[ -e /dev/net/tun ] && chmod 666 /dev/net/tun 2>/dev/null || true
exec runuser -u runner -- /usr/local/bin/socialweb-nodeboot "$@"
