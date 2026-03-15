FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    slapd ldap-utils python3 procps \
    libsasl2-2 libsasl2-modules \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Custom schemas
COPY schema/ /etc/ldap/schema/custom/

# SASL config — tells slapd to use the mux socket for password checks
COPY sasl2/slapd.conf /etc/ldap/sasl2/slapd.conf

# slapd config template (populated by entrypoint.sh)
COPY slapd.conf.tpl /etc/ldap/slapd.conf.tpl

# Python application
COPY app/ /opt/app/

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/lib/ldap /var/run/slapd /var/run/saslauthd

WORKDIR /opt

EXPOSE 3389 6636

ENTRYPOINT ["/entrypoint.sh"]
