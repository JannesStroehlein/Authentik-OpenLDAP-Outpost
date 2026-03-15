# ==========================================================================
# OpenLDAP slapd configuration — Authentik Federation
# ==========================================================================
# Generated from slapd.conf.tpl by entrypoint.sh.
# Password authentication is delegated to authentik via SASL pass-through
# to our Python auth_server.py (replaces saslauthd).
# ==========================================================================

# Schemas
include     /etc/ldap/schema/core.schema
include     /etc/ldap/schema/cosine.schema
include     /etc/ldap/schema/inetorgperson.schema
# NIS overlay: posixAccount + posixGroup as AUXILIARY
include     /etc/ldap/schema/custom/00-nis-overlay.schema
# Authentik outpost-compatible objectClasses
include     /etc/ldap/schema/custom/01-authentik.schema

# Modules
modulepath  /usr/lib/ldap
moduleload  back_mdb

# Logging
loglevel    %%SLAPD_LOG_LEVEL%%

# PID / args
pidfile     /var/run/slapd/slapd.pid
argsfile    /var/run/slapd/slapd.args

# ---- Access Control ----
access to attrs=userPassword
    by dn.exact="cn=admin,%%BASE_DN%%" write
    by self read
    by anonymous auth
    by * none

access to *
    by dn.exact="cn=admin,%%BASE_DN%%" write
    by users read
    by anonymous read

# ---- Database ----
database    mdb
suffix      "%%BASE_DN%%"
rootdn      "cn=admin,%%BASE_DN%%"
rootpw      %%ROOT_PW_HASH%%

maxsize     1073741824
directory   /var/lib/ldap

# Indices
index       objectClass     eq
index       cn              eq,sub
index       uid             eq
index       mail            eq,sub
index       member          eq
index       gidNumber       eq
index       uidNumber       eq
index       entryCSN        eq
index       entryUUID       eq
