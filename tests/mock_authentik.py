#!/usr/bin/env python3
"""Mock authentik API server for testing.

Serves canned user/group data and implements a minimal flow executor
for bind authentication testing.

Test credentials: alice/alice-secret (success), anything else (failure).
"""

import json
from datetime import UTC, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from authentik_client.models.group import Group
from authentik_client.models.paginated_group_list import PaginatedGroupList
from authentik_client.models.paginated_user_list import PaginatedUserList
from authentik_client.models.pagination import Pagination
from authentik_client.models.partial_user import PartialUser
from authentik_client.models.user import User
from authentik_client.models.user_type_enum import UserTypeEnum


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _build_user(
    *,
    pk: int,
    username: str,
    name: str,
    email: str,
    is_active: bool,
    attributes: dict,
    is_superuser: bool = False,
) -> User:
    user = User(
        pk=pk,
        username=username,
        name=name,
        is_active=is_active,
        is_superuser=is_superuser,
        date_joined=_dt("2024-01-01T12:00:00Z"),
        password_change_date=_dt("2024-01-02T12:00:00Z"),
        last_updated=_dt("2024-01-03T12:00:00Z"),
        uuid=f"00000000-0000-0000-0000-000000000{pk:03d}",
        uid=f"uid-{pk}",
        avatar=f"https://cdn.test.local/avatar/{username}.png",
        email=email,
        type=UserTypeEnum("internal"),
        path="users/",
        groups=[],
        groups_obj=[],
        roles=[],
        roles_obj=[],
        attributes=attributes,
        last_login=None,
    )
    return user


def _build_group(
    *,
    num_pk: int,
    group_uuid: str,
    name: str,
    attributes: dict,
    users_obj: list[dict],
) -> Group:
    partial_users = [PartialUser(**item) for item in users_obj]
    group = Group(
        pk=group_uuid,
        num_pk=num_pk,
        name=name,
        is_superuser=False,
        parents=[],
        parents_obj=[],
        users=[item["pk"] for item in users_obj],
        users_obj=partial_users,
        attributes=attributes,
        roles=[],
        roles_obj=[],
        inherited_roles_obj=[],
        children=[],
        children_obj=[],
    )
    return group

_USER_RESULTS = [
        _build_user(
            pk=1,
            username="alice",
            name="Alice Admin",
            email="alice@test.local",
            is_active=True,
            is_superuser=True,
            attributes={
                "mailAlias": ["alice.admin@test.local", "a@test.local"],
                "mailList": "dev-announce@test.local",
                "isSuperuser": True,
                "employeeNumber": 1001,
                "departmentCodes": ["ENG", "PLATFORM", 7],
                "profile": {"timezone": "Europe/Berlin", "locale": "en-US"},
                "webauthn_devices": 2,
            },
        ),
        _build_user(
            pk=2,
            username="bob",
            name="Bob Builder",
            email="bob@test.local",
            is_active=True,
            attributes={
                "mailAlias": "bobby@test.local",
            },
        ),
        _build_user(
            pk=3,
            username="charlie",
            name="Charlie Chaplin",
            email="charlie@test.local",
            is_active=False,
            attributes={},
        ),
]

USERS = PaginatedUserList(
    pagination=Pagination(
        count=3,
        next=0,
        previous=0,
        current=1,
        total_pages=1,
        start_index=1,
        end_index=3,
    ),
    results=_USER_RESULTS,
    autocomplete={},
).model_dump(mode="json")

_GROUP_RESULTS = [
    _build_group(
        num_pk=1,
        group_uuid="aaaaaaaa-1111-2222-3333-444444444444",
        name="admins",
        attributes={
            "systemMail": "admins@test.local",
            "mailAlias": ["admin-team@test.local"],
            "isPrivileged": True,
            "costCenter": 9001,
            "entitlements": ["vpn", "k8s-admin"],
            "authentikMeta": {"owner": "security", "tier": 1},
        },
        users_obj=[
            {"pk": 1, "username": "alice", "name": "Alice Admin", "uid": "uid-1"},
            {"pk": 2, "username": "bob", "name": "Bob Builder", "uid": "uid-2"},
        ],
    ),
    _build_group(
        num_pk=2,
        group_uuid="bbbbbbbb-1111-2222-3333-444444444444",
        name="developers",
        attributes={
            "systemMail": "dev@test.local",
        },
        users_obj=[
            {"pk": 1, "username": "alice", "name": "Alice Admin", "uid": "uid-1"},
            {"pk": 3, "username": "charlie", "name": "Charlie Chaplin", "uid": "uid-3"},
        ],
    ),
    _build_group(
        num_pk=3,
        group_uuid="cccccccc-1111-2222-3333-444444444444",
        name="empty-group",
        attributes={},
        users_obj=[],
    ),
    _build_group(
        num_pk=4,
        group_uuid="dddddddd-1111-2222-3333-444444444444",
        name="ldap-search-access",
        attributes={},
        users_obj=[
            {"pk": 1, "username": "alice", "name": "Alice Admin", "uid": "uid-1"},
        ],
    ),
]

GROUPS = PaginatedGroupList(
    pagination=Pagination(
        count=4,
        next=0,
        previous=0,
        current=1,
        total_pages=1,
        start_index=1,
        end_index=3,
    ),
    results=_GROUP_RESULTS,
    autocomplete={},
).model_dump(mode="json")

# Valid test credentials for flow executor
VALID_USERS = {
    "alice": "alice-secret",
    "bob": "bob-secret",
}

# Per-session flow state (keyed by session cookie)
_flow_sessions: dict[str, dict] = {}
_session_counter = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/v3/core/users/"):
            self._json_response(USERS)
        elif self.path.startswith("/api/v3/core/groups/"):
            self._json_response(GROUPS)
        elif self.path.startswith("/api/v3/flows/executor/"):
            # GET = start flow -> identification challenge
            session_id = self._get_or_create_session()
            _flow_sessions[session_id] = {"stage": "identification"}
            self._json_response(
                {"component": "ak-stage-identification", "type": "native", "password_fields": True},
                cookies={"ak_session": session_id},
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if not self.path.startswith("/api/v3/flows/executor/"):
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length)) if content_length else {}

        session_id = self._get_session()
        if not session_id or session_id not in _flow_sessions:
            self._json_response(
                {"component": "ak-stage-access-denied", "type": "native"}, status=403
            )
            return

        session = _flow_sessions[session_id]

        if session["stage"] == "identification":
            session["username"] = body.get("uid_field", "")
            if "password" in body:
                # Inline password (password_fields: true) -> validate now
                password = body["password"]
                expected = VALID_USERS.get(session["username"])
                del _flow_sessions[session_id]
                if expected and password == expected:
                    self._json_response(
                        {"component": "xak-flow-redirect", "type": "redirect", "to": "/"}
                    )
                else:
                    self._json_response(
                        {"component": "ak-stage-access-denied", "type": "native"}
                    )
                return
            # No password submitted -> move to separate password stage
            session["stage"] = "password"
            self._json_response(
                {"component": "ak-stage-password", "type": "native"}
            )

        elif session["stage"] == "password":
            # Received password -> check credentials
            username = session.get("username", "")
            password = body.get("password", "")
            expected = VALID_USERS.get(username)

            del _flow_sessions[session_id]

            if expected and password == expected:
                self._json_response(
                    {"component": "xak-flow-redirect", "type": "redirect", "to": "/"}
                )
            else:
                self._json_response(
                    {"component": "ak-stage-access-denied", "type": "native"}
                )
        else:
            del _flow_sessions[session_id]
            self._json_response(
                {"component": "ak-stage-access-denied", "type": "native"}, status=403
            )

    def _json_response(self, data, status=200, cookies=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookies:
            for name, value in cookies.items():
                self.send_header("Set-Cookie", f"{name}={value}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def _get_or_create_session(self) -> str:
        session_id = self._get_session()
        if session_id:
            return session_id
        global _session_counter
        _session_counter += 1
        return f"session-{_session_counter}"

    def _get_session(self) -> str | None:
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("ak_session="):
                return part.split("=", 1)[1]
        return None

    def log_message(self, fmt, *args):
        print(f"mock-authentik: {fmt % args}", flush=True)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("Mock authentik API listening on :8080", flush=True)
    server.serve_forever()
