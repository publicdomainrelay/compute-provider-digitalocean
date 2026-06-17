# Build: deno task build:vm
FROM fedora:latest

RUN dnf install -y \
    qemu-system-x86-core \
    e2fsprogs \
    openssh-clients \
    unzip \
 && dnf clean all

WORKDIR /app
COPY qemu-standalone .

ENTRYPOINT ["/app/qemu-standalone", "run"]
