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
moduleload  memberof

# Logging
loglevel    %%SLAPD_LOG_LEVEL%%

# PID / args
pidfile     /var/run/slapd/slapd.pid
argsfile    /var/run/slapd/slapd.args

# ---- Access Control ----
# Runtime config DB (cn=config): allow local EXTERNAL root to manage schema.
database    config
rootdn      "cn=admin,cn=config"
access to *
    by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage
    by * none

# ---- Database ----
database    mdb
suffix      "%%BASE_DN%%"

# Main data DB ACLs
#
# userPassword: IPC root can write (sync), user can read own, anonymous
# can only use it for bind authentication.
access to attrs=userPassword
    by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" write
    by anonymous auth
    by * none

# Everything else: IPC root can write, members of the search-access group
# can read the full directory, all other users can only read themselves.
# Anonymous gets no read access.
access to *
    by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" write
    by group/groupOfNames/member="cn=%%SEARCH_GROUP%%,ou=groups,%%BASE_DN%%" read
    by self read
    by anonymous auth
    by * none

maxsize     1073741824
directory   /var/lib/ldap

# Indices
index       objectClass     eq
index       cn              eq,sub
index       uid             eq
index       mail            eq,sub
index       member          eq
index       memberOf        eq
index       gidNumber       eq
index       uidNumber       eq
index       entryCSN        eq
index       entryUUID       eq

# TLS (populated by entrypoint.sh if certs are present)
%%TLS_CONFIG%%

# memberof overlay: auto-populate memberOf on user entries from group member attrs
overlay     memberof
memberof-group-oc       groupOfNames
memberof-member-ad      member
memberof-memberof-ad    memberOf
memberof-dangling       ignore
memberof-refint         false
