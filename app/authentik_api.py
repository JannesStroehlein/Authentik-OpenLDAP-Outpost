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
            log.warning("TLS certificate verification is DISABLED — connections to Authentik are vulnerable to MITM attacks")
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

    def get_all_users(self, page_size: int) -> list[authentik_client.User]:
        """
        Fetch all users from the authentik API.
        """
        results: list[authentik_client.User] = []
        page = 1
        while True:
            response = self._core_api.core_users_list(page=page, page_size=page_size)
            page_users = response.results
            results.extend(page_users or [])
            if response.pagination.total_pages == response.pagination.current:
                break
            page = response.pagination.next
        return results

    def get_all_groups(self, page_size: int, include_users: bool) -> list[authentik_client.Group]:
        """
        Fetch all groups from the authentik API.
        """
        results: list[authentik_client.Group] = []
        page = 1
        while True:
            response = self._core_api.core_groups_list(
                page=page,
                page_size=page_size,
                include_users=include_users,
            )
            page_groups = response.results
            results.extend(page_groups or [])
            if response.pagination.total_pages == response.pagination.current:
                break
            page = response.pagination.next
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
