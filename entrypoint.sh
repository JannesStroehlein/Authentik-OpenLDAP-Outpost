#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
LDAP_BASE_DN="${LDAP_BASE_DN:-DC=ldap,DC=goauthentik,DC=io}"
LDAP_PORT="${LDAP_PORT:-3389}"
LDAP_SEARCH_ACCESS_GROUP="${LDAP_SEARCH_ACCESS_GROUP:-ldap-search-access}"
SLAPD_LOG_LEVEL="${SLAPD_LOG_LEVEL:-256}"
SLAPD_CONFIG_DIR="${SLAPD_CONFIG_DIR:-/var/lib/ldap/slapd.d}"

# ---------------------------------------------------------------------------
# 1. TLS certificate setup
# ---------------------------------------------------------------------------
LDAP_TLS_CERT="${LDAP_TLS_CERT:-}"
LDAP_TLS_KEY="${LDAP_TLS_KEY:-}"
LDAP_TLS_CA="${LDAP_TLS_CA:-}"
TLS_CONFIG=""

if [ -n "$LDAP_TLS_CERT" ] && [ -n "$LDAP_TLS_KEY" ]; then
    TLS_CONFIG="TLSCertificateFile    ${LDAP_TLS_CERT}
TLSCertificateKeyFile ${LDAP_TLS_KEY}"
    if [ -n "$LDAP_TLS_CA" ]; then
        TLS_CONFIG="${TLS_CONFIG}
TLSCACertificateFile  ${LDAP_TLS_CA}"
    fi
    echo "TLS configured (cert: ${LDAP_TLS_CERT})"
elif [ ! -f /etc/ldap/certs/ldap.crt ]; then
    # Generate self-signed cert for LDAPS if no cert provided
    mkdir -p /etc/ldap/certs
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/ldap/certs/ldap.key \
        -out /etc/ldap/certs/ldap.crt \
        -days 3650 -subj "/CN=ldap" 2>/dev/null
    chown openldap:openldap /etc/ldap/certs/ldap.key /etc/ldap/certs/ldap.crt
    chmod 600 /etc/ldap/certs/ldap.key
    TLS_CONFIG="TLSCertificateFile    /etc/ldap/certs/ldap.crt
TLSCertificateKeyFile /etc/ldap/certs/ldap.key"
    echo "TLS configured (self-signed certificate generated)"
else
    TLS_CONFIG="TLSCertificateFile    /etc/ldap/certs/ldap.crt
TLSCertificateKeyFile /etc/ldap/certs/ldap.key"
    echo "TLS configured (existing self-signed certificate)"
fi

# ---------------------------------------------------------------------------
# 1.1 Generate slapd.conf from template
# ---------------------------------------------------------------------------
printf '%s\n' "$TLS_CONFIG" > /tmp/tls_config.txt
sed \
    -e "s|%%BASE_DN%%|${LDAP_BASE_DN}|g" \
    -e "s|%%SEARCH_GROUP%%|${LDAP_SEARCH_ACCESS_GROUP}|g" \
    -e "s|%%SLAPD_LOG_LEVEL%%|${SLAPD_LOG_LEVEL}|g" \
    /etc/ldap/slapd.conf.tpl | sed -e '/%%TLS_CONFIG%%/{
r /tmp/tls_config.txt
d
}' > /etc/ldap/slapd.conf
rm -f /tmp/tls_config.txt

echo "Generated slapd.conf (base DN: ${LDAP_BASE_DN})"

# ---------------------------------------------------------------------------
# 2. Fix permissions
# ---------------------------------------------------------------------------
chown -R openldap:openldap /var/lib/ldap /var/run/slapd
mkdir -p /var/run/saslauthd

# ---------------------------------------------------------------------------
# 2.1 Regenerate dynamic cn=config from template on each startup
# ---------------------------------------------------------------------------
echo "Rendering dynamic config at $SLAPD_CONFIG_DIR ..."
rm -rf "$SLAPD_CONFIG_DIR"
mkdir -p "$SLAPD_CONFIG_DIR"
slaptest -f /etc/ldap/slapd.conf -F "$SLAPD_CONFIG_DIR"
chown -R openldap:openldap "$SLAPD_CONFIG_DIR"

# ---------------------------------------------------------------------------
# 3. Start auth_server.py (replaces saslauthd)
# ---------------------------------------------------------------------------
echo "Starting auth_server.py..."
uv run --no-sync -m app.auth_server &
AUTH_PID=$!

sleep 1

if ! kill -0 "$AUTH_PID" 2>/dev/null; then
    echo "ERROR: auth_server.py failed to start"
    exit 1
fi

if [ -S /var/run/saslauthd/mux ]; then
    echo "auth_server.py is running, socket at /var/run/saslauthd/mux"
else
    echo "WARNING: mux socket not found, SASL pass-through auth may not work"
fi

# ---------------------------------------------------------------------------
# 4. Start slapd
# ---------------------------------------------------------------------------
LDAPS_PORT="${LDAPS_PORT:-6636}"
echo "Starting slapd on port ${LDAP_PORT} (ldap) and ${LDAPS_PORT} (ldaps)..."
/usr/sbin/slapd \
    -h "ldap://0.0.0.0:${LDAP_PORT}/ ldaps://0.0.0.0:${LDAPS_PORT}/ ldapi:///" \
    -F "$SLAPD_CONFIG_DIR" \
    -u openldap \
    -g openldap \
    -d "${SLAPD_LOG_LEVEL}" &
SLAPD_PID=$!

sleep 1

if ! kill -0 "$SLAPD_PID" 2>/dev/null; then
    echo "ERROR: slapd failed to start"
    exit 1
fi
echo "slapd started (PID ${SLAPD_PID})"

# ---------------------------------------------------------------------------
# 5. Background monitor — exit container if slapd or auth_server die
# ---------------------------------------------------------------------------
(
    while true; do
        if ! kill -0 "$SLAPD_PID" 2>/dev/null; then
            echo "ERROR: slapd (PID ${SLAPD_PID}) died, exiting container"
            kill $$ 2>/dev/null
            exit 1
        fi
        if ! kill -0 "$AUTH_PID" 2>/dev/null; then
            echo "ERROR: auth_server.py (PID ${AUTH_PID}) died, exiting container"
            kill $$ 2>/dev/null
            exit 1
        fi
        sleep 5
    done
) &

# ---------------------------------------------------------------------------
# 6. Run sync.py in foreground (keeps container alive)
# ---------------------------------------------------------------------------
echo "Starting sync.py..."
exec uv run --no-sync -m app.sync
