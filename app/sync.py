"""Authentik -> OpenLDAP directory sync.

Polls the authentik REST API for users and groups, converts them to LDIF,
and loads them into the local slapd via ldapadd/ldapdelete.

General-purpose: attribute mapping matches the authentik LDAP outpost.
Custom user/group attributes are passed through via extensibleObject.
"""

import logging
import os
import re
import subprocess
import sys
import time
from typing import Any

from .authentik_api import AuthentikClient

log = logging.getLogger("ldap-sync")

# Valid LDAP attribute name: starts with letter, then letters/digits/hyphens
_VALID_ATTR_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")


class LDAPSync:
    """Sync authentik users and groups into a local slapd."""

    def __init__(
        self,
        client: AuthentikClient,
        base_dn: str,
        bind_dn: str,
        bind_pw: str,
        ldap_uri: str = "ldap://localhost:3389",
    ) -> None:
        self.client = client
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.ldap_uri = ldap_uri

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

        # Wipe existing entries
        self._wipe_entries()

        # Create base structure
        log.info("Creating base structure...")
        self._ldap_add(self._build_base_ldif())

        # Create user entries
        log.info("Creating %d user entries...", len(users))
        for user in users:
            entry = self._build_user_entry(user)
            if entry:
                self._ldap_add_entry(entry)

        # Create group entries
        log.info("Creating %d group entries...", len(groups))
        for group in groups:
            entry = self._build_group_entry(group, members_by_group)
            if entry:
                self._ldap_add_entry(entry)

        log.info("Sync complete.")
        return True

    # ----- LDIF builders -----

    def _build_base_ldif(self) -> str:
        dc = self.base_dn.split(",")[0].split("=")[1]
        return (
            f"dn: {self.base_dn}\n"
            f"objectClass: top\n"
            f"objectClass: organization\n"
            f"objectClass: dcObject\n"
            f"o: authentik\n"
            f"dc: {dc}\n"
            f"\n"
            f"dn: ou=users,{self.base_dn}\n"
            f"objectClass: top\n"
            f"objectClass: organizationalUnit\n"
            f"ou: users\n"
            f"\n"
            f"dn: ou=groups,{self.base_dn}\n"
            f"objectClass: top\n"
            f"objectClass: organizationalUnit\n"
            f"ou: groups\n\n"
        )

    def _build_user_entry(self, user: dict[str, Any]) -> str:
        username = user.get("username", "")
        if not username:
            return ""

        dn = f"cn={username},ou=users,{self.base_dn}"
        name = user.get("name", username)
        email = user.get("email", "")
        is_active = user.get("is_active", False)
        uid_number = user.get("pk", 1000)
        attrs = user.get("attributes", {})

        lines = [
            f"dn: {dn}",
            "objectClass: top",
            "objectClass: person",
            "objectClass: organizationalPerson",
            "objectClass: inetOrgPerson",
            "objectClass: posixAccount",
            "objectClass: goauthentik-io-ldap-user",
            "objectClass: extensibleObject",
            f"cn: {username}",
            f"uid: {username}",
            f"sn: {name.split()[-1] if ' ' in name else name}",
            f"displayName: {name}",
            f"uidNumber: {uid_number + 10000}",
            f"gidNumber: 10000",
            f"homeDirectory: /home/{username}",
        ]

        if ' ' in name:
            lines.append(f"givenName: {name.split()[0]}")

        lines.append(f"loginShell: {'/bin/bash' if is_active else '/sbin/nologin'}")

        if email:
            lines.append(f"mail: {email}")

        # Custom attributes pass-through (skip invalid LDAP attr names)
        for key, value in attrs.items():
            if not _VALID_ATTR_NAME.match(key):
                continue
            if isinstance(value, list):
                for v in value:
                    if v is not None and v != "":
                        lines.append(f"{key}: {v}")
            elif isinstance(value, bool):
                lines.append(f"{key}: {'TRUE' if value else 'FALSE'}")
            elif value is not None and value != "":
                lines.append(f"{key}: {value}")

        # SASL pass-through password
        lines.append(f"userPassword: {{SASL}}{username}@authentik")
        lines.append("")

        return "\n".join(lines) + "\n"

    def _build_group_entry(
        self, group: dict[str, Any], members: dict[str, list[str]]
    ) -> str:
        group_name = group.get("name", "")
        if not group_name:
            return ""

        dn = f"cn={group_name},ou=groups,{self.base_dn}"
        gid_raw = group.get("pk", "")
        attrs = group.get("attributes", {})

        lines = [
            f"dn: {dn}",
            "objectClass: top",
            "objectClass: groupOfNames",
            "objectClass: posixGroup",
            "objectClass: goauthentik-io-ldap-group",
            "objectClass: extensibleObject",
            f"cn: {group_name}",
        ]

        # gidNumber: hash UUID strings, offset ints
        if isinstance(gid_raw, str):
            lines.append(f"gidNumber: {abs(hash(gid_raw)) % 60000 + 10000}")
        else:
            lines.append(f"gidNumber: {gid_raw + 20000}")

        # Members
        member_names = members.get(group.get("pk", ""), [])
        if member_names:
            for uname in member_names:
                lines.append(f"member: cn={uname},ou=users,{self.base_dn}")
        else:
            lines.append(f"member: cn=_placeholder,ou=users,{self.base_dn}")

        # Custom attributes pass-through (skip invalid LDAP attr names)
        for key, value in attrs.items():
            if not _VALID_ATTR_NAME.match(key):
                continue
            if isinstance(value, list):
                for v in value:
                    if v is not None and v != "":
                        lines.append(f"{key}: {v}")
            elif isinstance(value, bool):
                lines.append(f"{key}: {'TRUE' if value else 'FALSE'}")
            elif isinstance(value, object):
                lines.append(f"{key}: {str(value)}")
            elif value is not None and value != "":
                lines.append(f"{key}: {value}")

        lines.append("")
        return "\n".join(lines) + "\n"

    # ----- LDAP operations -----

    def _ldap_add(self, ldif: str) -> int:
        result = subprocess.run(
            [
                "ldapadd", "-x", "-H", self.ldap_uri,
                "-D", self.bind_dn, "-w", self.bind_pw, "-c",
            ],
            input=ldif.encode("utf-8"),
            capture_output=True,
        )
        if result.returncode not in (0, 68):  # 68 = already exists
            stderr = result.stderr.decode("utf-8", errors="replace")
            if "Already exists" not in stderr:
                log.warning("ldapadd returned %d: %s", result.returncode, stderr[:500])
        return result.returncode

    def _ldap_add_entry(self, ldif: str) -> bool:
        """Add a single LDIF entry, stripping undefined attributes on retry."""
        all_bad: set[str] = set()
        current = ldif
        for _ in range(5):  # max retries
            result = subprocess.run(
                [
                    "ldapadd", "-x", "-H", self.ldap_uri,
                    "-D", self.bind_dn, "-w", self.bind_pw,
                ],
                input=current.encode("utf-8"),
                capture_output=True,
            )
            if result.returncode in (0, 68):
                return True
            if result.returncode != 17:
                stderr = result.stderr.decode("utf-8", errors="replace")
                if "Already exists" not in stderr:
                    log.warning("ldapadd returned %d: %s", result.returncode, stderr[:300])
                return False
            # Parse bad attribute name from stderr (undefined or invalid chars)
            stderr = result.stderr.decode("utf-8", errors="replace")
            new_bad: set[str] = set()
            for line in stderr.splitlines():
                if "attribute type undefined" in line or "inappropriate characters" in line:
                    parts = line.split("additional info: ", 1)
                    if len(parts) == 2:
                        attr_name = parts[1].split(":")[0].strip()
                        if attr_name and attr_name not in all_bad:
                            new_bad.add(attr_name)
            if not new_bad:
                return False
            all_bad.update(new_bad)
            log.info("Stripping undefined attrs: %s", ", ".join(sorted(all_bad)))
            filtered = []
            for line in ldif.splitlines():
                if any(
                    line.startswith(f"{a}: ") or line.startswith(f"{a}:: ")
                    for a in all_bad
                ):
                    continue
                filtered.append(line)
            current = "\n".join(filtered) + "\n"
        return False

    def _wipe_entries(self) -> None:
        """Delete all entries under base DN (deepest first)."""
        log.info("Deleting existing LDAP entries...")
        result = subprocess.run(
            [
                "ldapsearch", "-x", "-H", self.ldap_uri,
                "-D", self.bind_dn, "-w", self.bind_pw,
                "-b", self.base_dn, "-s", "sub", "dn", "-LLL",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            return

        dns: list[str] = []
        for line in result.stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("dn: "):
                dns.append(line[4:])

        # Delete deepest first
        dns.reverse()
        for dn in dns:
            subprocess.run(
                [
                    "ldapdelete", "-x", "-H", self.ldap_uri,
                    "-D", self.bind_dn, "-w", self.bind_pw, dn,
                ],
                capture_output=True,
            )

    def _wait_for_slapd(self, timeout: int = 120) -> bool:
        """Wait until slapd is accepting connections."""
        log.info("Waiting for slapd at %s ...", self.ldap_uri)
        for _ in range(timeout):
            result = subprocess.run(
                [
                    "ldapsearch", "-x", "-H", self.ldap_uri,
                    "-b", "", "-s", "base", "objectClass=*", "-LLL",
                ],
                capture_output=True,
            )
            if result.returncode == 0:
                log.info("slapd is ready.")
                return True
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
    admin_pw = os.environ.get("LDAP_ADMIN_PASSWORD", "admin")
    bind_dn = f"cn=admin,{base_dn}"
    ldap_port = os.environ.get("LDAP_PORT", "3389")
    ldap_uri = f"ldap://localhost:{ldap_port}"
    interval = int(os.environ.get("SYNC_INTERVAL", "300"))

    client = AuthentikClient(url, token, verify_tls)
    sync = LDAPSync(client, base_dn, bind_dn, admin_pw, ldap_uri)
    sync.run_forever(interval)


if __name__ == "__main__":
    main()
