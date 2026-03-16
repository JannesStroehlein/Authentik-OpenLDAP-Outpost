"""Authentik -> OpenLDAP directory sync.

Polls the authentik REST API for users and groups, converts them to LDIF,
and loads them into the local slapd via ldap3 over ldapi IPC.

General-purpose: attribute mapping matches the authentik LDAP outpost.
Custom user/group attributes are passed through via extensibleObject.
"""

import copy
import hashlib
import json
import logging
import os
import re
import sys
import time
from typing import Any

from ldap3 import (
    ALL_ATTRIBUTES,
    BASE,
    MODIFY_ADD,
    SUBTREE,
    Connection,
    SASL,
    Server,
    EXTERNAL,
)
from ldap3.utils.dn import escape_rdn

from .authentik_api import AuthentikClient

log = logging.getLogger("ldap-sync")

# Valid LDAP attribute name: starts with letter, then letters/digits/hyphens
_VALID_ATTR_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")
_BAD_ATTR_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9-]*)\s*:\s*(attribute type undefined|inappropriate characters)",
    re.IGNORECASE,
)
_ATTR_OID_PREFIX = "1.3.6.1.4.1.55555.1"

_BUILTIN_USER_ATTRS = {
    "cn", "uid", "sn", "displayName", "uidNumber", "gidNumber",
    "homeDirectory", "loginShell", "userPassword", "givenName", "mail",
}

_BUILTIN_GROUP_ATTRS = {"cn", "gidNumber", "member"}
_BUILTIN_USER_ATTRS_LOWER = {attr.lower() for attr in _BUILTIN_USER_ATTRS}
_BUILTIN_GROUP_ATTRS_LOWER = {attr.lower() for attr in _BUILTIN_GROUP_ATTRS}

# Characters that are unsafe in LDAP DN values, filesystem paths, or SASL identities
_UNSAFE_NAME_RE = re.compile(r"[\x00/]")
# Max length for usernames and group names used in DNs
_MAX_NAME_LENGTH = 256


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

            # Ensure schema exists for authentik custom attributes.
            self._ensure_dynamic_schema(conn, users, groups)

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

    @staticmethod
    def _validate_name(name: str, kind: str) -> bool:
        """Reject names that are empty, too long, or contain unsafe characters."""
        if not name or len(name) > _MAX_NAME_LENGTH:
            log.warning("Skipping %s with invalid name (empty or too long): %r", kind, name[:64])
            return False
        if _UNSAFE_NAME_RE.search(name):
            log.warning("Skipping %s with unsafe characters in name: %r", kind, name[:64])
            return False
        return True

    def _user_dn(self, username: str) -> str:
        return f"cn={escape_rdn(username)},ou=users,{self.base_dn}"

    def _group_dn(self, group_name: str) -> str:
        return f"cn={escape_rdn(group_name)},ou=groups,{self.base_dn}"

    def _build_user_entry(self, user: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]] | None:
        username = user.get("username", "")
        if not self._validate_name(username, "user"):
            return None

        dn = self._user_dn(username)
        name = user.get("name", username)
        email = user.get("email", "")
        is_active = user.get("is_active", False)
        uid_number = user.get("pk", 1000)
        custom_attrs = user.get("attributes", {})
        safe_username = username.replace("/", "_").replace("\x00", "")

        attrs: dict[str, Any] = {
            "cn": username,
            "uid": username,
            "sn": name.split()[-1] if " " in name else name,
            "displayName": name,
            "uidNumber": str(uid_number + 10000),
            "gidNumber": "10000",
            "homeDirectory": f"/home/{safe_username}",
            "loginShell": "/bin/bash" if is_active else "/sbin/nologin",
            "userPassword": f"{{SASL}}{username}@authentik",
        }

        if " " in name:
            attrs["givenName"] = name.split()[0]

        if email:
            attrs["mail"] = email

        # Custom attributes pass-through (case-insensitive key merge)
        for key, values in self._normalized_custom_attrs(custom_attrs, _BUILTIN_USER_ATTRS_LOWER).items():
            attrs[key] = values[0] if len(values) == 1 else values

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
        if not self._validate_name(group_name, "group"):
            return None

        dn = self._group_dn(group_name)
        gid_raw = group.get("pk", "")
        attrs = group.get("attributes", {})

        entry_attrs: dict[str, Any] = {
            "cn": group_name,
        }

        # gidNumber: deterministic hash for UUID strings, offset for ints
        if isinstance(gid_raw, str):
            gid_hash = int.from_bytes(
                hashlib.sha256(gid_raw.encode()).digest()[:4], "big"
            )
            entry_attrs["gidNumber"] = str(gid_hash % 60000 + 10000)
        else:
            entry_attrs["gidNumber"] = str(gid_raw + 20000)

        # Members
        member_names = members.get(group.get("pk", ""), [])
        if member_names:
            entry_attrs["member"] = [self._user_dn(uname) for uname in member_names]
        else:
            entry_attrs["member"] = f"cn=_placeholder,ou=users,{self.base_dn}"

        # Custom attributes pass-through (case-insensitive key merge)
        for key, values in self._normalized_custom_attrs(attrs, _BUILTIN_GROUP_ATTRS_LOWER).items():
            entry_attrs[key] = values[0] if len(values) == 1 else values

        object_classes = [
            "top",
            "groupOfNames",
            "posixGroup",
            "goauthentik-io-ldap-group",
            "extensibleObject",
        ]
        return dn, object_classes, entry_attrs

    # ----- LDAP operations (ldapi + EXTERNAL) -----

    @staticmethod
    def _to_ldap_value(value: Any) -> str:
        if isinstance(value, bool):
            return "TRUE" if value else "FALSE"
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        return str(value)

    def _normalized_custom_attrs(
        self,
        raw_attrs: dict[str, Any],
        builtin_lower: set[str],
    ) -> dict[str, list[str]]:
        canonical_name_by_lower: dict[str, str] = {}
        merged: dict[str, list[str]] = {}

        for key, value in raw_attrs.items():
            if not _VALID_ATTR_NAME.match(key):
                continue

            key_lower = key.lower()
            if key_lower in builtin_lower:
                continue

            canonical = canonical_name_by_lower.setdefault(key_lower, key)

            if isinstance(value, list):
                values = [self._to_ldap_value(v) for v in value if v is not None and v != ""]
            elif value is None or value == "":
                values = []
            else:
                values = [self._to_ldap_value(value)]

            if not values:
                continue

            target = merged.setdefault(canonical, [])
            for item in values:
                if item not in target:
                    target.append(item)

        return merged

    @staticmethod
    def _parse_attr_names(attr_type: str) -> set[str]:
        names: set[str] = set()
        multi = re.search(r"\bNAME\s+\(([^)]*)\)", attr_type)
        if multi:
            for match in re.findall(r"'([^']+)'", multi.group(1)):
                names.add(match)
            return names
        single = re.search(r"\bNAME\s+'([^']+)'", attr_type)
        if single:
            names.add(single.group(1))
        return names

    @staticmethod
    def _parse_attr_oid(attr_type: str) -> str | None:
        match = re.match(r"\s*\(\s*([0-9.]+)", attr_type)
        if not match:
            return None
        return match.group(1)

    def _schema_state(self, conn: Connection) -> tuple[set[str], set[str]]:
        if not conn.search(
            search_base="cn=Subschema",
            search_filter="(objectClass=subschema)",
            search_scope=BASE,
            attributes=["attributeTypes"],
        ):
            return set(), set()

        name_set: set[str] = set()
        oid_set: set[str] = set()
        for entry in conn.entries:
            for attr_type in entry["attributeTypes"].values:
                name_set.update(self._parse_attr_names(str(attr_type)))
                oid = self._parse_attr_oid(str(attr_type))
                if oid:
                    oid_set.add(oid)
        return name_set, oid_set

    def _desired_custom_attr_names(
        self,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> set[str]:
        canonical_name_by_lower: dict[str, str] = {}
        for user in users:
            for key in (user.get("attributes", {}) or {}).keys():
                if not _VALID_ATTR_NAME.match(key):
                    continue
                key_lower = key.lower()
                if key_lower in _BUILTIN_USER_ATTRS_LOWER:
                    continue
                canonical_name_by_lower.setdefault(key_lower, key)
        for group in groups:
            for key in (group.get("attributes", {}) or {}).keys():
                if not _VALID_ATTR_NAME.match(key):
                    continue
                key_lower = key.lower()
                if key_lower in _BUILTIN_GROUP_ATTRS_LOWER:
                    continue
                canonical_name_by_lower.setdefault(key_lower, key)
        return set(canonical_name_by_lower.values())

    @staticmethod
    def _oid_for_name(name: str, used_oids: set[str]) -> str:
        base_num = int.from_bytes(hashlib.sha1(name.encode("utf-8")).digest()[:4], "big")
        candidate = base_num
        while True:
            oid = f"{_ATTR_OID_PREFIX}.{candidate}"
            if oid not in used_oids:
                return oid
            candidate += 1

    @staticmethod
    def _attr_type_definition(name: str, oid: str) -> str:
        return (
            f"( {oid} NAME '{name}' "
            "DESC 'Auto-generated from authentik custom attributes' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

    def _ensure_dynamic_schema(
        self,
        conn: Connection,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> None:
        desired = self._desired_custom_attr_names(users, groups)
        if not desired:
            return

        existing_names, used_oids = self._schema_state(conn)
        existing_names_lower = {name.lower() for name in existing_names}
        missing = sorted(name for name in desired if name.lower() not in existing_names_lower)
        if not missing:
            return

        definitions: list[str] = []
        for name in missing:
            oid = self._oid_for_name(name, used_oids)
            used_oids.add(oid)
            definitions.append(self._attr_type_definition(name, oid))

        if not conn.search(
            search_base="cn=schema,cn=config",
            search_filter="(cn=authentikDynamic)",
            search_scope=SUBTREE,
            attributes=["cn"],
        ):
            if not conn.add(
                "cn=authentikDynamic,cn=schema,cn=config",
                object_class=["top", "olcSchemaConfig"],
                attributes={"cn": "authentikDynamic", "olcAttributeTypes": definitions},
            ):
                log.warning("Failed to create dynamic schema: %s", conn.result)
                return
            log.info("Created dynamic schema with %d attribute types", len(definitions))
            return

        schema_dn = conn.entries[0].entry_dn
        if not conn.modify(schema_dn, {"olcAttributeTypes": [(MODIFY_ADD, definitions)]}):
            log.warning("Failed to update dynamic schema: %s", conn.result)
            return
        log.info("Added %d dynamic attribute types", len(definitions))

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
        # Groups must be deleted before users so the memberof overlay can
        # clean up memberOf attributes while the user entries still exist.
        dns = [dn for dn in dns if dn.lower() != self.base_dn.lower()]
        dns.sort(key=lambda dn: (-dn.count(","), 0 if "ou=groups" in dn.lower() else 1))
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
