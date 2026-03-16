"""Shared authentik REST API client for sync and authentication."""

import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

import authentik_client
from authentik_client.api.core_api import CoreApi

log = logging.getLogger("authentik-api")


class AuthentikClient:
    """Reusable client for the authentik REST API."""

    def __init__(self, url: str, token: str, verify_tls: bool = True) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.ssl_ctx: ssl.SSLContext | None = None
        if not verify_tls:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

        cfg = authentik_client.Configuration(
            host=f"{self.url}/api/v3",
            access_token=self.token,
        )
        cfg.verify_ssl = verify_tls
        self._api_client = authentik_client.ApiClient(cfg)
        self._core_api = CoreApi(self._api_client)

    # ----- paginated API fetch (Bearer token auth) -----

    def get_paginated(self, path: str) -> list[dict[str, Any]]:
        """Fetch all pages from an authentik API endpoint.

        Uses authentik-client for known endpoints and falls back to raw HTTP for
        any other path.
        """
        parsed = urllib.parse.urlparse(path)
        endpoint_path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if endpoint_path.startswith("/api/v3/core/users/"):
            try:
                return self._get_users_via_client(query)
            except Exception as exc:
                log.warning("SDK client failed for users, falling back to raw HTTP: %s", exc)
        if endpoint_path.startswith("/api/v3/core/groups/"):
            try:
                return self._get_groups_via_client(query)
            except Exception as exc:
                log.warning("SDK client failed for groups, falling back to raw HTTP: %s", exc)

        return self._get_paginated_raw(path)

    def _get_users_via_client(self, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        page_size = int(query.get("page_size", ["500"])[0])
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            response = self._core_api.core_users_list(page=page, page_size=page_size)
            page_items = [item.model_dump(mode="json") for item in (response.results or [])]
            results.extend(page_items)
            if not getattr(response, "pagination", None) or not response.pagination.next:
                break
            page += 1
        return results

    def _get_groups_via_client(self, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        page_size = int(query.get("page_size", ["500"])[0])
        include_users = query.get("include_users", ["false"])[0].lower() == "true"
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            response = self._core_api.core_groups_list(
                page=page,
                page_size=page_size,
                include_users=include_users,
            )
            page_items = [item.model_dump(mode="json") for item in (response.results or [])]
            results.extend(page_items)
            if not getattr(response, "pagination", None) or not response.pagination.next:
                break
            page += 1
        return results

    def _get_paginated_raw(self, path: str) -> list[dict[str, Any]]:
        """Fallback: paginated raw HTTP call for unknown endpoints."""
        results: list[dict[str, Any]] = []
        url: str | None = f"{self.url}{path}"
        while url:
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(req, context=self.ssl_ctx) as resp:
                    data = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                log.error("API %s failed: %s %s", url, exc.code, exc.reason)
                raise
            results.extend(data.get("results", []))
            url = data.get("pagination", {}).get("next")
        return results

    # ----- flow executor authentication -----

    def authenticate_user(self, username: str, password: str, flow_slug: str) -> bool:
        """Walk the authentik flow executor to verify credentials.

        Returns True on successful authentication, False otherwise.
        """
        base = f"{self.url}/api/v3/flows/executor/{flow_slug}/"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
                return None

        jar = CookieJar()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(jar),
            _NoRedirect(),
        ]
        if self.ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.ssl_ctx))
        opener = urllib.request.build_opener(*handlers)

        try:
            # Start flow
            req = self._flow_request(base)
            with opener.open(req) as resp:
                stage = json.loads(resp.read().decode())

            # Handle flexible flow shapes (identification/password/prompt/etc.)
            seen: set[tuple[str, str]] = set()
            for _ in range(10):
                component = str(stage.get("component", ""))
                stage_type = str(stage.get("type", ""))
                sig = (component, stage_type)
                if sig in seen:
                    log.warning("Flow executor loop detected at stage: %s", component)
                    return False
                seen.add(sig)

                if component == "xak-flow-redirect" or stage_type == "redirect":
                    return True
                if component == "ak-stage-access-denied":
                    return False

                payload_dict = self._payload_for_stage(stage, username, password)
                if payload_dict is None:
                    log.warning("Unsupported flow stage for LDAP auth: %s", component)
                    return False

                req = self._flow_request(base, data=json.dumps(payload_dict).encode())
                try:
                    with opener.open(req) as resp:
                        stage = json.loads(resp.read().decode())
                except urllib.error.HTTPError as exc:
                    if exc.code in (301, 302, 303, 307, 308):
                        return True
                    if exc.code in (400, 401, 403):
                        return False
                    raise

            log.warning("Flow executor exceeded max stage transitions")
            return False

        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403):
                return False
            log.error("Flow executor HTTP error: %s %s", exc.code, exc.reason)
            return False
        except Exception:
            log.exception("Flow executor error")
            return False

    def _flow_request(self, url: str, data: bytes | None = None) -> urllib.request.Request:
        """Build a request for the flow executor."""
        req = urllib.request.Request(url, data=data, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        return req

    @staticmethod
    def _payload_for_stage(stage: dict, username: str, password: str) -> dict[str, Any] | None:
        """Build best-effort payload for common authentik stages.

        Supports standard and ldap-auth-flow variations, including
        identification stages with an inline password_stage.
        """
        component = str(stage.get("component", ""))
        component_lower = component.lower()

        if component == "ak-stage-identification" or "identification" in component_lower:
            payload: dict[str, Any] = {
                "uid_field": username,
                "username": username,
            }
            if stage.get("password_fields"):
                payload["password"] = password
            return payload

        if component == "ak-stage-password" or "password" in component_lower:
            return {"password": password}

        if component == "ak-stage-prompt" or "prompt" in component_lower:
            return {
                "uid_field": username,
                "username": username,
                "password": password,
            }

        return None
