FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-scapy \
    isc-dhcp-server isc-dhcp-client \
    iptables iproute2 iputils-ping net-tools tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
