#!/bin/bash
set -e

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
LDAP_BASE_DN="${LDAP_BASE_DN:-DC=ldap,DC=goauthentik,DC=io}"
LDAP_PORT="${LDAP_PORT:-3389}"
SLAPD_LOG_LEVEL="${SLAPD_LOG_LEVEL:-256}"
SLAPD_CONFIG_DIR="${SLAPD_CONFIG_DIR:-/var/lib/ldap/slapd.d}"

# ---------------------------------------------------------------------------
# 1. Generate slapd.conf from template
# ---------------------------------------------------------------------------
sed \
    -e "s|%%BASE_DN%%|${LDAP_BASE_DN}|g" \
    -e "s|%%SLAPD_LOG_LEVEL%%|${SLAPD_LOG_LEVEL}|g" \
    /etc/ldap/slapd.conf.tpl > /etc/ldap/slapd.conf

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
echo "Starting slapd on port ${LDAP_PORT}..."
/usr/sbin/slapd \
    -h "ldap://0.0.0.0:${LDAP_PORT}/ ldapi:///" \
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
