#!/bin/bash
#
# Integration tests for the OpenLDAP Authentik Federation stack.
#
# Builds the image, starts services with mock authentik API, waits for
# sync to complete, then runs ldapsearch/ldapwhoami queries to verify
# sync correctness, objectClass filters, bind auth, and search scopes.
#
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.test.yml -p ak-ldap-test"
LDAP_URI="ldap://localhost:3389"
BASE_DN="DC=ldap,DC=goauthentik,DC=io"

# Bind credentials for authenticated searches (alice is in ldap-search-access group)
BIND_DN="cn=alice,ou=users,$BASE_DN"
BIND_PW="alice-secret"

PASS=0
FAIL=0
TESTS=0

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    $COMPOSE down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

assert_count() {
    local description="$1"
    local expected="$2"
    local filter="$3"
    local search_base="${4:-$BASE_DN}"

    TESTS=$((TESTS + 1))
    local output
    output=$(ldapsearch -x -H "$LDAP_URI" \
        -D "$BIND_DN" -w "$BIND_PW" \
        -b "$search_base" "$filter" dn -LLL 2>/dev/null)
    local count
    count=$(echo "$output" | grep -c "^dn:" || true)

    if [ "$count" -eq "$expected" ]; then
        echo "  PASS: $description (found $count)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected $expected, got $count)"
        echo "        filter: $filter"
        echo "        output: $output"
        FAIL=$((FAIL + 1))
    fi
}

assert_attr() {
    local description="$1"
    local dn="$2"
    local attr="$3"
    local expected="$4"

    TESTS=$((TESTS + 1))
    local output
    output=$(ldapsearch -x -H "$LDAP_URI" \
        -D "$BIND_DN" -w "$BIND_PW" \
        -b "$dn" -s base "(objectClass=*)" "$attr" -LLL 2>/dev/null)

    # Check plain text match first, then try base64-decoded values
    if echo "$output" | grep -qi "$attr: $expected"; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    elif echo "$output" | grep "^$attr::" | while read -r line; do
            decoded=$(echo "$line" | sed "s/^$attr:: //" | base64 -d 2>/dev/null)
            echo "$decoded"
        done | grep -qi "$expected"; then
        echo "  PASS: $description (base64)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$attr: $expected')"
        echo "        output: $output"
        FAIL=$((FAIL + 1))
    fi
}

assert_attr_count() {
    local description="$1"
    local dn="$2"
    local attr="$3"
    local expected="$4"

    TESTS=$((TESTS + 1))
    local output
    output=$(ldapsearch -x -H "$LDAP_URI" \
        -D "$BIND_DN" -w "$BIND_PW" \
        -b "$dn" -s base "(objectClass=*)" "$attr" -LLL 2>/dev/null)
    local count
    count=$(echo "$output" | grep -ci "^$attr:" || true)

    if [ "$count" -eq "$expected" ]; then
        echo "  PASS: $description ($count values)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected $expected values, got $count)"
        echo "        output: $output"
        FAIL=$((FAIL + 1))
    fi
}

assert_no_attr() {
    local description="$1"
    local dn="$2"
    local attr="$3"

    TESTS=$((TESTS + 1))
    local output
    output=$(ldapsearch -x -H "$LDAP_URI" \
        -D "$BIND_DN" -w "$BIND_PW" \
        -b "$dn" -s base "(objectClass=*)" "$attr" -LLL 2>/dev/null)

    if echo "$output" | grep -qi "^$attr:"; then
        echo "  FAIL: $description (unexpected attribute '$attr' present)"
        echo "        output: $output"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    fi
}

# =========================================================================
echo "=== Building and starting test environment ==="
# =========================================================================
$COMPOSE build --quiet
$COMPOSE up -d

# Expose slapd on host port 3389 for test queries
$COMPOSE down openldap 2>/dev/null || true
$COMPOSE run -d --name ak-ldap-test-openldap -p 3389:389 openldap

echo ""
echo "=== Waiting for sync to complete ==="
for i in $(seq 1 90); do
    if docker logs ak-ldap-test-openldap 2>&1 | grep -q "Sync complete"; then
        echo "  Sync completed after ~${i}s"
        break
    fi
    if [ "$i" -eq 90 ]; then
        echo "  TIMEOUT waiting for sync"
        echo ""
        echo "=== Container logs ==="
        docker logs ak-ldap-test-openldap 2>&1 | tail -60
        exit 1
    fi
    sleep 1
done

# Give slapd a moment to index
sleep 1

echo ""
echo "=== Running tests ==="

# -------------------------------------------------------------------------
echo ""
echo "--- Base structure ---"
# -------------------------------------------------------------------------
assert_count "Base DN exists" 1 "(objectClass=organization)" "$BASE_DN"
assert_count "ou=users exists" 1 "(objectClass=organizationalUnit)" "ou=users,$BASE_DN"
assert_count "ou=groups exists" 1 "(objectClass=organizationalUnit)" "ou=groups,$BASE_DN"

# -------------------------------------------------------------------------
echo ""
echo "--- Users ---"
# -------------------------------------------------------------------------
assert_count "3 users synced" 3 "(objectClass=posixAccount)" "ou=users,$BASE_DN"
assert_count "alice exists" 1 "(cn=alice)" "ou=users,$BASE_DN"
assert_count "bob exists" 1 "(cn=bob)" "ou=users,$BASE_DN"
assert_count "charlie exists" 1 "(cn=charlie)" "ou=users,$BASE_DN"

assert_attr "alice email" "cn=alice,ou=users,$BASE_DN" "mail" "alice@test.local"
assert_attr "bob email" "cn=bob,ou=users,$BASE_DN" "mail" "bob@test.local"

# Custom attributes pass-through: mailAlias
assert_attr_count "alice has 2 mailAlias" "cn=alice,ou=users,$BASE_DN" "mailAlias" 2
assert_attr_count "bob has 1 mailAlias" "cn=bob,ou=users,$BASE_DN" "mailAlias" 1

# loginShell: active vs inactive
assert_attr "alice active (loginShell)" "cn=alice,ou=users,$BASE_DN" "loginShell" "/bin/bash"
assert_attr "charlie inactive (loginShell)" "cn=charlie,ou=users,$BASE_DN" "loginShell" "/sbin/nologin"

# userPassword should not be readable by other authenticated users
TESTS=$((TESTS + 1))
pw_output=$(ldapsearch -x -H "$LDAP_URI" \
    -D "$BIND_DN" -w "$BIND_PW" \
    -b "cn=bob,ou=users,$BASE_DN" -s base "(objectClass=*)" "userPassword" -LLL 2>/dev/null)
if echo "$pw_output" | grep -qi "^userPassword:"; then
    echo "  FAIL: bob userPassword should not be readable by alice"
    echo "        output: $pw_output"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: bob userPassword is not readable by other users"
    PASS=$((PASS + 1))
fi

# Custom attribute pass-through: mailList
assert_attr "alice mailList" "cn=alice,ou=users,$BASE_DN" "mailList" "dev-announce@test.local"
assert_attr "alice isSuperuser bool" "cn=alice,ou=users,$BASE_DN" "isSuperuser" "TRUE"
assert_attr "alice employeeNumber passthrough" "cn=alice,ou=users,$BASE_DN" "employeeNumber" "1001"
assert_attr_count "alice has 3 departmentCodes" "cn=alice,ou=users,$BASE_DN" "departmentCodes" 3
assert_attr "alice profile serialized" "cn=alice,ou=users,$BASE_DN" "profile" "{\"locale\":\"en-US\",\"timezone\":\"Europe/Berlin\"}"
assert_no_attr "alice invalid attr dropped" "cn=alice,ou=users,$BASE_DN" "webauthn_devices"

# -------------------------------------------------------------------------
echo ""
echo "--- Groups ---"
# -------------------------------------------------------------------------
assert_count "4 groups synced" 4 "(objectClass=posixGroup)" "ou=groups,$BASE_DN"

assert_attr "admins systemMail" "cn=admins,ou=groups,$BASE_DN" "systemMail" "admins@test.local"
assert_attr "developers systemMail" "cn=developers,ou=groups,$BASE_DN" "systemMail" "dev@test.local"

# admins group has alice + bob
assert_attr_count "admins has 2 members" "cn=admins,ou=groups,$BASE_DN" "member" 2
# developers has alice + charlie
assert_attr_count "developers has 2 members" "cn=developers,ou=groups,$BASE_DN" "member" 2
# empty-group has placeholder
assert_attr_count "empty-group has placeholder member" "cn=empty-group,ou=groups,$BASE_DN" "member" 1
assert_attr "empty-group placeholder DN" "cn=empty-group,ou=groups,$BASE_DN" "member" "cn=_placeholder,ou=users,$BASE_DN"

assert_attr "admins mailAlias" "cn=admins,ou=groups,$BASE_DN" "mailAlias" "admin-team@test.local"
assert_attr "admins isPrivileged bool" "cn=admins,ou=groups,$BASE_DN" "isPrivileged" "TRUE"
assert_attr "admins costCenter int" "cn=admins,ou=groups,$BASE_DN" "costCenter" "9001"
assert_attr_count "admins has 2 entitlements" "cn=admins,ou=groups,$BASE_DN" "entitlements" 2
assert_attr "admins authentikMeta serialized" "cn=admins,ou=groups,$BASE_DN" "authentikMeta" "{\"owner\":\"security\",\"tier\":1}"

# -------------------------------------------------------------------------
echo ""
echo "--- memberOf (overlay) ---"
# -------------------------------------------------------------------------
# alice is in admins + developers + ldap-search-access
assert_attr_count "alice has 3 memberOf" "cn=alice,ou=users,$BASE_DN" "memberOf" 3
assert_attr "alice memberOf admins" "cn=alice,ou=users,$BASE_DN" "memberOf" "cn=admins,ou=groups,$BASE_DN"
assert_attr "alice memberOf developers" "cn=alice,ou=users,$BASE_DN" "memberOf" "cn=developers,ou=groups,$BASE_DN"
assert_attr "alice memberOf ldap-search-access" "cn=alice,ou=users,$BASE_DN" "memberOf" "cn=ldap-search-access,ou=groups,$BASE_DN"

# bob is in admins only
assert_attr_count "bob has 1 memberOf" "cn=bob,ou=users,$BASE_DN" "memberOf" 1
assert_attr "bob memberOf admins" "cn=bob,ou=users,$BASE_DN" "memberOf" "cn=admins,ou=groups,$BASE_DN"

# charlie is in developers only
assert_attr_count "charlie has 1 memberOf" "cn=charlie,ou=users,$BASE_DN" "memberOf" 1
assert_attr "charlie memberOf developers" "cn=charlie,ou=users,$BASE_DN" "memberOf" "cn=developers,ou=groups,$BASE_DN"

# filter by memberOf
assert_count "memberOf filter finds admins members" 2 \
    "(memberOf=cn=admins,ou=groups,$BASE_DN)" "ou=users,$BASE_DN"

# -------------------------------------------------------------------------
echo ""
echo "--- objectClass OR filter (the original bug) ---"
# -------------------------------------------------------------------------
assert_count \
    "OR filter: posixGroup first, then posixAccount" \
    1 \
    "(&(|(objectClass=posixGroup)(objectClass=posixAccount))(systemMail=admins@test.local))"

assert_count \
    "OR filter: posixAccount first, then posixGroup" \
    1 \
    "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(systemMail=admins@test.local))"

# Both users and groups in same query
assert_count \
    "OR filter: find all entries with mail containing 'test.local'" \
    5 \
    "(&(|(objectClass=posixAccount)(objectClass=posixGroup))(|(mail=*test.local*)(systemMail=*test.local*)))"

# -------------------------------------------------------------------------
echo ""
echo "--- Search scopes ---"
# -------------------------------------------------------------------------
# Subtree search from base should find everything (authenticated)
TESTS=$((TESTS + 1))
subtree_count=$(ldapsearch -x -H "$LDAP_URI" \
    -D "$BIND_DN" -w "$BIND_PW" \
    -b "$BASE_DN" -s sub "(objectClass=*)" dn -LLL 2>/dev/null | grep -c "^dn:" || true)
if [ "$subtree_count" -ge 10 ]; then  # base + 2 OUs + 3 users + 4 groups
    echo "  PASS: Subtree search from base (found $subtree_count entries)"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Subtree search from base (expected >= 10, got $subtree_count)"
    FAIL=$((FAIL + 1))
fi

# One-level search from ou=users should find only users
assert_count "One-level search in ou=users" 3 "(objectClass=posixAccount)" "ou=users,$BASE_DN"

# Base scope on a specific user (authenticated)
TESTS=$((TESTS + 1))
base_output=$(ldapsearch -x -H "$LDAP_URI" \
    -D "$BIND_DN" -w "$BIND_PW" \
    -b "cn=alice,ou=users,$BASE_DN" -s base "(objectClass=*)" cn -LLL 2>/dev/null)
if echo "$base_output" | grep -q "cn: alice"; then
    echo "  PASS: Base scope search on alice"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Base scope search on alice"
    FAIL=$((FAIL + 1))
fi

# -------------------------------------------------------------------------
echo ""
echo "--- BIND authentication via flow executor ---"
# -------------------------------------------------------------------------
# Successful bind with alice/alice-secret
TESTS=$((TESTS + 1))
if ldapwhoami -x -H "$LDAP_URI" \
    -D "cn=alice,ou=users,$BASE_DN" -w "alice-secret" 2>/dev/null | grep -q "dn:"; then
    echo "  PASS: BIND alice with correct password"
    PASS=$((PASS + 1))
else
    echo "  FAIL: BIND alice with correct password"
    FAIL=$((FAIL + 1))
fi

# Failed bind with wrong password
TESTS=$((TESTS + 1))
if ! ldapwhoami -x -H "$LDAP_URI" \
    -D "cn=alice,ou=users,$BASE_DN" -w "wrong-password" 2>/dev/null | grep -q "dn:"; then
    echo "  PASS: BIND alice with wrong password rejected"
    PASS=$((PASS + 1))
else
    echo "  FAIL: BIND alice with wrong password was accepted"
    FAIL=$((FAIL + 1))
fi

# Admin bind must fail (admin user removed)
TESTS=$((TESTS + 1))
if ! ldapwhoami -x -H "$LDAP_URI" -D "cn=admin,$BASE_DN" -w "testpassword" 2>/dev/null | grep -q "dn:"; then
    echo "  PASS: Admin BIND rejected"
    PASS=$((PASS + 1))
else
    echo "  FAIL: Admin BIND unexpectedly succeeded"
    FAIL=$((FAIL + 1))
fi

# -------------------------------------------------------------------------
echo ""
echo "--- ACL: anonymous read denied ---"
# -------------------------------------------------------------------------
TESTS=$((TESTS + 1))
anon_output=$(ldapsearch -x -H "$LDAP_URI" -b "ou=users,$BASE_DN" "(cn=alice)" cn -LLL 2>/dev/null || true)
if echo "$anon_output" | grep -q "cn: alice"; then
    echo "  FAIL: Anonymous read should be denied"
    echo "        output: $anon_output"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: Anonymous read denied"
    PASS=$((PASS + 1))
fi

# -------------------------------------------------------------------------
echo ""
echo "--- ACL: non-privileged user can only read self ---"
# -------------------------------------------------------------------------
# bob is NOT in ldap-search-access group — should only see his own entry
TESTS=$((TESTS + 1))
bob_self=$(ldapsearch -x -H "$LDAP_URI" \
    -D "cn=bob,ou=users,$BASE_DN" -w "bob-secret" \
    -b "cn=bob,ou=users,$BASE_DN" -s base "(objectClass=*)" cn -LLL 2>/dev/null || true)
if echo "$bob_self" | grep -q "cn: bob"; then
    echo "  PASS: bob can read his own entry"
    PASS=$((PASS + 1))
else
    echo "  FAIL: bob cannot read his own entry"
    echo "        output: $bob_self"
    FAIL=$((FAIL + 1))
fi

TESTS=$((TESTS + 1))
bob_alice=$(ldapsearch -x -H "$LDAP_URI" \
    -D "cn=bob,ou=users,$BASE_DN" -w "bob-secret" \
    -b "cn=alice,ou=users,$BASE_DN" -s base "(objectClass=*)" cn -LLL 2>/dev/null || true)
if echo "$bob_alice" | grep -q "cn: alice"; then
    echo "  FAIL: bob should not be able to read alice's entry"
    echo "        output: $bob_alice"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: bob cannot read alice's entry"
    PASS=$((PASS + 1))
fi

# -------------------------------------------------------------------------
echo ""
echo "--- ACL: privileged user (ldap-search-access) can read full dir ---"
# -------------------------------------------------------------------------
TESTS=$((TESTS + 1))
alice_all=$(ldapsearch -x -H "$LDAP_URI" \
    -D "$BIND_DN" -w "$BIND_PW" \
    -b "ou=users,$BASE_DN" "(objectClass=posixAccount)" dn -LLL 2>/dev/null)
alice_all_count=$(echo "$alice_all" | grep -c "^dn:" || true)
if [ "$alice_all_count" -eq 3 ]; then
    echo "  PASS: alice (ldap-search-access) can read all users ($alice_all_count)"
    PASS=$((PASS + 1))
else
    echo "  FAIL: alice should read all 3 users (got $alice_all_count)"
    echo "        output: $alice_all"
    FAIL=$((FAIL + 1))
fi

# -------------------------------------------------------------------------
echo ""
echo "--- Custom attribute pass-through ---"
# -------------------------------------------------------------------------
# Verify extensibleObject allows arbitrary attributes from authentik
assert_attr "alice mailList pass-through" "cn=alice,ou=users,$BASE_DN" "mailList" "dev-announce@test.local"
assert_attr "admins systemMail pass-through" "cn=admins,ou=groups,$BASE_DN" "systemMail" "admins@test.local"

# =========================================================================
echo ""
echo "==========================================="
echo "  Results: $PASS passed, $FAIL failed (of $TESTS)"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Container logs (last 40 lines) ==="
    docker logs ak-ldap-test-openldap 2>&1 | tail -40
    exit 1
fi
