# OpenLDAP Authentik Sync

Mostly drop in replacement for the official Authentik LDAP outpost, which has frustrated me due to it's inability to respond correctly to the simplest of LDAP filter expressions (see [Authentik/#2756](https://github.com/goauthentik/authentik/issues/2756))

This replaces the Authentik LDAP outpost with a self-managed OpenLDAP instance while maintaining compatibility with the outpost's schema and attribute layout.

> [!CAUTION]
> This project may contain high severity security vulnerabilities and leak your Authentik directory to the internet.
> I don't give any guarantees that this project won't cause problems due to oversights on my part.

## Features

- Full LDAP filter support (including those mean `(|(objectClass=posixAccount)(objectClass=groupOfNames))` filters)
- `memberOf` overlay for group membership attributes on user entries
- single container deployment
- dynamic schema generation for custom attributes from Authentik (only way OpenLDAP supports custom attributes)
- TLS support for secure LDAP (LDAPS)
- Access Control: only users in the configured group can read the full directory
- Flow based authentication: bind requests are delegated to Authentik's flow executor

## How it works

```
                  Authentik REST API
                    |           ^
          sync (poll)           | flow executor (auth)
                    v           |
               +--------------------+
               |   sync.py          |  Fetches users/groups, writes LDIF
               |   auth_server.py   |  SASL mux socket, credential cache
               |   slapd            |  OpenLDAP with memberof overlay
               +--------------------+
                    |
              ldap(s)://
                    |
               LDAP clients
```

- **sync.py** polls the Authentik API on an interval, wipes the directory, and rebuilds all user/group entries with custom attributes passed through.
- **auth_server.py** listens on a Unix socket (saslauthd mux protocol). When slapd receives a bind request, it delegates password verification through this socket to Authentik's flow executor.
- **slapd** serves the directory over LDAP/LDAPS. The `memberof` overlay automatically maintains `memberOf` attributes on user entries.

## Quick start

```bash
cp .env.example .env   # set AUTHENTIK_URL and AUTHENTIK_TOKEN
docker compose up -d
```

Test with:

```bash
ldapsearch -x -H ldap://localhost:3389 -b "DC=ldap,DC=goauthentik,DC=io" "(objectClass=posixAccount)"
```

## Configuration

All configuration is via environment variables:

| Variable                   | Default                        | Description                                            |
| -------------------------- | ------------------------------ | ------------------------------------------------------ |
| `AUTHENTIK_URL`            | _required_                     | Base URL of your Authentik instance                    |
| `AUTHENTIK_TOKEN`          | _required_                     | API token with read access to users/groups             |
| `AUTHENTIK_AUTH_FLOW_SLUG` | `default-authentication-flow`  | Flow slug used for bind authentication                 |
| `LDAP_BASE_DN`             | `DC=ldap,DC=goauthentik,DC=io` | LDAP directory base DN                                 |
| `LDAP_PORT`                | `3389`                         | LDAP listen port                                       |
| `LDAPS_PORT`               | `6636`                         | LDAPS (TLS) listen port                                |
| `SYNC_INTERVAL`            | `300`                          | Seconds between sync cycles                            |
| `BIND_CACHE_TTL`           | `300`                          | Seconds to cache successful bind credentials           |
| `VERIFY_TLS`               | `true`                         | Verify Authentik's TLS certificate                     |
| `LOG_LEVEL`                | `INFO`                         | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### TLS

LDAPS is enabled by default. Without custom certificates, a self-signed certificate is generated on first start. To use your own:

| Variable        | Description                                     |
| --------------- | ----------------------------------------------- |
| `LDAP_TLS_CERT` | Path to TLS certificate file (inside container) |
| `LDAP_TLS_KEY`  | Path to TLS private key file                    |
| `LDAP_TLS_CA`   | Path to CA certificate file (optional)          |

Mount your certificate files into the container and set the paths.

### Authentik setup

1. Create an API token in Authentik with read access to users and groups.
2. Create or identify an authentication flow for LDAP binds (e.g. `ldap-authentication-flow`). The flow needs an identification stage with a password stage — either inline (`password_stage` on the identification stage) or as a separate binding.

## Schema

User entries use these object classes: `inetOrgPerson`, `posixAccount`, `goauthentik-io-ldap-user`, `extensibleObject`.

Group entries use: `groupOfNames`, `posixGroup`, `goauthentik-io-ldap-group`, `extensibleObject`.

Custom attributes from Authentik are passed through as LDAP attributes via `extensibleObject`. Dynamic schema entries are created automatically for attribute names matching `^[a-zA-Z][a-zA-Z0-9-]*$`.

## Running tests

```bash
cd tests
bash run_tests.sh
```

Requires Docker. Builds the image, starts a mock Authentik API server, syncs data, then runs ldapsearch/ldapwhoami assertions covering sync correctness, objectClass filters, memberOf overlay, bind auth, search scopes, and ACLs.
