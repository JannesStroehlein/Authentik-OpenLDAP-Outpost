#!/usr/bin/env python3
"""Mock authentik API server for testing.

Serves canned user/group data and implements a minimal flow executor
for bind authentication testing.

Test credentials: alice/alice-secret (success), anything else (failure).
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

USERS = {
    "results": [
        {
            "pk": 1,
            "username": "alice",
            "name": "Alice Admin",
            "email": "alice@test.local",
            "is_active": True,
            "attributes": {
                "mailAlias": ["alice.admin@test.local", "a@test.local"],
                "mailList": "dev-announce@test.local",
                "isSuperuser": True,
                "employeeNumber": 1001,
                "departmentCodes": ["ENG", "PLATFORM", 7],
                "profile": {"timezone": "Europe/Berlin", "locale": "en-US"},
                "webauthn_devices": 2,
            },
        },
        {
            "pk": 2,
            "username": "bob",
            "name": "Bob Builder",
            "email": "bob@test.local",
            "is_active": True,
            "attributes": {
                "mailAlias": "bobby@test.local",
            },
        },
        {
            "pk": 3,
            "username": "charlie",
            "name": "Charlie Chaplin",
            "email": "charlie@test.local",
            "is_active": False,
            "attributes": {},
        },
    ],
    "pagination": {"next": None, "count": 3},
}

GROUPS = {
    "results": [
        {
            "pk": "aaaaaaaa-1111-2222-3333-444444444444",
            "name": "admins",
            "attributes": {
                "systemMail": "admins@test.local",
                "mailAlias": ["admin-team@test.local"],
                "isPrivileged": True,
                "costCenter": 9001,
                "entitlements": ["vpn", "k8s-admin"],
                "authentikMeta": {"owner": "security", "tier": 1},
            },
            "users_obj": [
                {"pk": 1, "username": "alice"},
                {"pk": 2, "username": "bob"},
            ],
        },
        {
            "pk": "bbbbbbbb-1111-2222-3333-444444444444",
            "name": "developers",
            "attributes": {
                "systemMail": "dev@test.local",
            },
            "users_obj": [
                {"pk": 1, "username": "alice"},
                {"pk": 3, "username": "charlie"},
            ],
        },
        {
            "pk": "cccccccc-1111-2222-3333-444444444444",
            "name": "empty-group",
            "attributes": {},
            "users_obj": [],
        },
    ],
    "pagination": {"next": None, "count": 3},
}

# Valid test credentials for flow executor
VALID_USERS = {
    "alice": "alice-secret",
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
                {"component": "ak-stage-identification", "type": "native"},
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
            # Received username -> move to password stage
            session["username"] = body.get("uid_field", "")
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
