FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 libpcap0.8t64 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
