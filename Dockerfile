FROM ghcr.io/astral-sh/uv:0.7.20 AS uvbin

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    slapd ldap-utils python3 procps \
    libsasl2-2 libsasl2-modules \
    ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uvbin /uv /usr/local/bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/.venv

# Custom schemas
COPY schema/ /etc/ldap/schema/custom/

# SASL config — tells slapd to use the mux socket for password checks
COPY sasl2/slapd.conf /etc/ldap/sasl2/slapd.conf

# slapd config template (populated by entrypoint.sh)
COPY slapd.conf.tpl /etc/ldap/slapd.conf.tpl

# Python dependency metadata
COPY pyproject.toml /opt/pyproject.toml

# Python application
COPY app/ /opt/app/

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    cd /opt && uv sync --no-dev && \
    mkdir -p /var/lib/ldap /var/run/slapd /var/run/saslauthd

WORKDIR /opt

EXPOSE 3389 6636

ENTRYPOINT ["/entrypoint.sh"]
