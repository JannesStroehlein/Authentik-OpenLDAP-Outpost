"""Authentik -> OpenLDAP directory sync.

Polls the authentik REST API for users and groups, converts them to LDIF,
and loads them into the local slapd via ldap3 over ldapi IPC.

General-purpose: attribute mapping matches the authentik LDAP outpost.
Custom user/group attributes are passed through via extensibleObject.
"""

import copy
import logging
import os
import re
import sys
import time
from typing import Any

from ldap3 import (
    ALL_ATTRIBUTES,
    BASE,
    SUBTREE,
    Connection,
    SASL,
    Server,
    EXTERNAL,
)

from .authentik_api import AuthentikClient

log = logging.getLogger("ldap-sync")

# Valid LDAP attribute name: starts with letter, then letters/digits/hyphens
_VALID_ATTR_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")
_BAD_ATTR_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9-]*)\s*:\s*(attribute type undefined|inappropriate characters)",
    re.IGNORECASE,
)


class LDAPSync:
    """Sync authentik users and groups into a local slapd."""

    def __init__(
        self,
        client: AuthentikClient,
        base_dn: str,
        ldap_uri: str = "ldapi:///",
    ) -> None:
        self.client = client
        self.base_dn = base_dn
        self.ldap_uri = ldap_uri

    def _candidate_uris(self) -> list[str]:
        if self.ldap_uri != "ldapi:///":
            return [self.ldap_uri]
        return [
            "ldapi://%2Frun%2Fslapd%2Fldapi",
            "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
            self.ldap_uri,
        ]

    def run_forever(self, interval: int) -> None:
        """Wait for slapd, then sync in a loop."""
        if not self._wait_for_slapd():
            sys.exit(1)
        while True:
            try:
                self.sync()
            except Exception:
                log.exception("Sync failed")
            log.info("Next sync in %d seconds", interval)
            time.sleep(interval)

    def sync(self) -> bool:
        """Full wipe-and-reload sync from authentik."""
        log.info("Starting sync from authentik API...")

        try:
            users = self.client.get_paginated("/api/v3/core/users/?page_size=500")
            groups = self.client.get_paginated(
                "/api/v3/core/groups/?page_size=500&include_users=true"
            )
        except Exception as exc:
            log.error("Failed to fetch from authentik: %s", exc)
            return False

        log.info("Fetched %d users and %d groups", len(users), len(groups))

        # Build member mapping: group pk -> list of usernames
        user_pk_to_name: dict[int, str] = {u["pk"]: u["username"] for u in users}
        members_by_group: dict[str, list[str]] = {}
        for g in groups:
            gpk = g.get("pk", "")
            group_users = g.get("users_obj", []) or g.get("users", [])
            names: list[str] = []
            for u in group_users:
                if isinstance(u, dict):
                    name = u.get("username", "")
                    if name:
                        names.append(name)
                elif isinstance(u, int):
                    name = user_pk_to_name.get(u)
                    if name:
                        names.append(name)
            members_by_group[gpk] = names

        conn: Connection | None = None
        try:
            conn = self._connect()

            # Wipe existing entries
            self._wipe_entries(conn)

            # Create base structure
            log.info("Creating base structure...")
            self._create_base_structure(conn)

            # Create user entries
            log.info("Creating %d user entries...", len(users))
            for user in users:
                entry = self._build_user_entry(user)
                if entry:
                    self._ldap_add_entry(conn, entry)

            # Create group entries
            log.info("Creating %d group entries...", len(groups))
            for group in groups:
                entry = self._build_group_entry(group, members_by_group)
                if entry:
                    self._ldap_add_entry(conn, entry)
        finally:
            if conn is not None:
                conn.unbind()

        log.info("Sync complete.")
        return True

    # ----- LDIF builders -----

    def _build_base_entries(self) -> list[tuple[str, list[str], dict[str, Any]]]:
        dc = self.base_dn.split(",")[0].split("=")[1]
        return [
            (
                self.base_dn,
                ["top", "organization", "dcObject"],
                {"o": "authentik", "dc": dc},
            ),
            (
                f"ou=users,{self.base_dn}",
                ["top", "organizationalUnit"],
                {"ou": "users"},
            ),
            (
                f"ou=groups,{self.base_dn}",
                ["top", "organizationalUnit"],
                {"ou": "groups"},
            ),
        ]

    def _build_user_entry(self, user: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]] | None:
        username = user.get("username", "")
        if not username:
            return None

        dn = f"cn={username},ou=users,{self.base_dn}"
        name = user.get("name", username)
        email = user.get("email", "")
        is_active = user.get("is_active", False)
        uid_number = user.get("pk", 1000)
        custom_attrs = user.get("attributes", {})

        attrs: dict[str, Any] = {
            "cn": username,
            "uid": username,
            "sn": name.split()[-1] if " " in name else name,
            "displayName": name,
            "uidNumber": str(uid_number + 10000),
            "gidNumber": "10000",
            "homeDirectory": f"/home/{username}",
            "loginShell": "/bin/bash" if is_active else "/sbin/nologin",
            "userPassword": f"{{SASL}}{username}@authentik",
        }

        if " " in name:
            attrs["givenName"] = name.split()[0]

        if email:
            attrs["mail"] = email

        # Custom attributes pass-through (skip invalid LDAP attr names)
        for key, value in custom_attrs.items():
            if not _VALID_ATTR_NAME.match(key):
                continue
            if isinstance(value, list):
                cleaned = [str(v) for v in value if v is not None and v != ""]
                if cleaned:
                    attrs[key] = cleaned
            elif isinstance(value, bool):
                attrs[key] = "TRUE" if value else "FALSE"
            elif value is not None and value != "":
                attrs[key] = str(value)

        object_classes = [
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "posixAccount",
            "goauthentik-io-ldap-user",
            "extensibleObject",
        ]
        return dn, object_classes, attrs

    def _build_group_entry(
        self, group: dict[str, Any], members: dict[str, list[str]]
    ) -> tuple[str, list[str], dict[str, Any]] | None:
        group_name = group.get("name", "")
        if not group_name:
            return None

        dn = f"cn={group_name},ou=groups,{self.base_dn}"
        gid_raw = group.get("pk", "")
        attrs = group.get("attributes", {})

        entry_attrs: dict[str, Any] = {
            "cn": group_name,
        }

        # gidNumber: hash UUID strings, offset ints
        if isinstance(gid_raw, str):
            entry_attrs["gidNumber"] = str(abs(hash(gid_raw)) % 60000 + 10000)
        else:
            entry_attrs["gidNumber"] = str(gid_raw + 20000)

        # Members
        member_names = members.get(group.get("pk", ""), [])
        if member_names:
            entry_attrs["member"] = [
                f"cn={uname},ou=users,{self.base_dn}" for uname in member_names
            ]
        else:
            entry_attrs["member"] = f"cn=_placeholder,ou=users,{self.base_dn}"

        # Custom attributes pass-through (skip invalid LDAP attr names)
        for key, value in attrs.items():
            if not _VALID_ATTR_NAME.match(key):
                continue
            if isinstance(value, list):
                cleaned = [str(v) for v in value if v is not None and v != ""]
                if cleaned:
                    entry_attrs[key] = cleaned
            elif isinstance(value, bool):
                entry_attrs[key] = "TRUE" if value else "FALSE"
            elif value is not None and value != "":
                entry_attrs[key] = str(value)

        object_classes = [
            "top",
            "groupOfNames",
            "posixGroup",
            "goauthentik-io-ldap-group",
            "extensibleObject",
        ]
        return dn, object_classes, entry_attrs

    # ----- LDAP operations (ldapi + EXTERNAL) -----

    def _connect(self) -> Connection:
        last_error: Exception | None = None
        for uri in self._candidate_uris():
            try:
                server = Server(uri, get_info=None)
                conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=EXTERNAL,
                    sasl_credentials="",
                    auto_bind=False,
                    check_names=False,
                    raise_exceptions=False,
                )

                for _ in range(3):
                    if conn.bind():
                        self.ldap_uri = uri
                        return conn
                    code = int((conn.result or {}).get("result", -1))
                    if code == 14:
                        continue
                    raise RuntimeError(f"LDAP bind failed for {uri}: {conn.result}")

                raise RuntimeError(f"LDAP bind did not complete for {uri}: {conn.result}")
            except Exception as exc:
                last_error = exc
                log.debug("LDAP connect failed for %s: %s", uri, exc)

        if last_error is not None:
            raise last_error
        raise RuntimeError("No LDAP URI candidates available")

    def _create_base_structure(self, conn: Connection) -> None:
        for dn, object_classes, attrs in self._build_base_entries():
            self._ldap_add_entry(conn, (dn, object_classes, attrs))

    def _ldap_add_entry(
        self,
        conn: Connection,
        entry: tuple[str, list[str], dict[str, Any]],
    ) -> bool:
        """Add a single entry, stripping undefined attributes on retry."""
        dn, object_classes, attrs = entry
        current_attrs = copy.deepcopy(attrs)
        all_bad: set[str] = set()
        for _ in range(5):  # max retries
            if conn.add(dn, object_class=object_classes, attributes=current_attrs):
                return True
            result = conn.result
            code = result.get("result", -1)
            if code == 68:
                return True
            if code != 17:
                msg = result.get("message", "")
                if "Already exists" not in msg:
                    log.warning("ldap add for %s returned %s: %s", dn, code, msg[:300])
                return False
            # Parse bad attribute name from server result
            msg = f"{result.get('message', '')} {result.get('description', '')}"
            new_bad: set[str] = set()
            for attr_name, _reason in _BAD_ATTR_RE.findall(msg):
                if attr_name not in all_bad:
                    new_bad.add(attr_name)
            if not new_bad:
                return False
            all_bad.update(new_bad)
            log.info("Stripping undefined attrs: %s", ", ".join(sorted(all_bad)))
            for bad_attr in all_bad:
                current_attrs.pop(bad_attr, None)
        return False

    def _wipe_entries(self, conn: Connection) -> None:
        """Delete all entries under base DN (deepest first)."""
        log.info("Deleting existing LDAP entries...")
        if not conn.search(
            search_base=self.base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=ALL_ATTRIBUTES,
        ):
            return

        dns: list[str] = [entry.entry_dn for entry in conn.entries]

        # Delete deepest first, keep base DN to be recreated explicitly.
        dns = [dn for dn in dns if dn.lower() != self.base_dn.lower()]
        dns.sort(key=lambda dn: dn.count(","), reverse=True)
        for dn in dns:
            conn.delete(dn)

    def _wait_for_slapd(self, timeout: int = 120) -> bool:
        """Wait until slapd is accepting connections."""
        log.info("Waiting for slapd at %s ...", self.ldap_uri)
        for _ in range(timeout):
            conn: Connection | None = None
            try:
                conn = self._connect()
                if conn.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=[],
                ):
                    log.info("slapd is ready.")
                    return True
            except Exception as exc:
                log.debug("slapd not ready yet: %s", exc)
            finally:
                if conn is not None:
                    conn.unbind()
            time.sleep(1)
        log.error("Timed out waiting for slapd.")
        return False


def main() -> None:
    """Entry point when run as a standalone script."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    url = os.environ["AUTHENTIK_URL"]
    token = os.environ["AUTHENTIK_TOKEN"]
    verify_tls = os.environ.get("VERIFY_TLS", "true").lower() == "true"
    base_dn = os.environ.get("LDAP_BASE_DN", "DC=ldap,DC=goauthentik,DC=io")
    ldap_uri = os.environ.get("LDAP_IPC_URI", "ldapi:///")
    interval = int(os.environ.get("SYNC_INTERVAL", "300"))

    client = AuthentikClient(url, token, verify_tls)
    sync = LDAPSync(client, base_dn, ldap_uri)
    sync.run_forever(interval)


if __name__ == "__main__":
    main()
