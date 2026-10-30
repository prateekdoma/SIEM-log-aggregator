FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        hydra \
        sshpass \
        openssh-client \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attacker
COPY wordlists/ ./wordlists/
COPY attack.sh /usr/local/bin/attack
COPY entrypoint.sh /usr/local/bin/entrypoint
RUN chmod +x /usr/local/bin/attack /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
