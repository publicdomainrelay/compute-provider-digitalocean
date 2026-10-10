# Build: deno task build:firecracker-runner
#
# One guest per container. The bidder runs where it runs and gives each guest a
# container with the three things booting a firecracker microVM needs and the
# bidder does not have: /dev/kvm, /dev/net/tun, and the capabilities pasta's tap
# setup uses. This is the same shape as hono-qemu-standalone and as the local
# provider's VM mode.
FROM fedora:latest

RUN dnf install -y \
    passt \
    e2fsprogs \
    iproute \
    util-linux \
    openssh-clients \
 && dnf clean all \
 && useradd -u 1000 -m -s /bin/sh runner

COPY firecracker /usr/local/bin/firecracker
COPY socialweb-nodeboot /usr/local/bin/socialweb-nodeboot
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/firecracker /usr/local/bin/socialweb-nodeboot /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
