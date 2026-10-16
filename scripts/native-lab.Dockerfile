FROM ubuntu:24.04
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates iproute2 openssl iputils-ping && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
