"""Shared authentik REST API client for sync and authentication."""

import json
import logging
import ssl
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any

log = logging.getLogger("authentik-api")


class AuthentikClient:
    """Reusable client for the authentik REST API."""

    def __init__(self, url: str, token: str, verify_tls: bool = True) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.ssl_ctx: ssl.SSLContext | None = None
        if not verify_tls:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    # ----- paginated API fetch (Bearer token auth) -----

    def get_paginated(self, path: str) -> list[dict[str, Any]]:
        """Fetch all pages from an authentik API endpoint."""
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
        jar = CookieJar()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(jar),
        ]
        if self.ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.ssl_ctx))
        opener = urllib.request.build_opener(*handlers)

        try:
            # Step 1: GET the flow — expect identification challenge
            req = self._flow_request(base)
            with opener.open(req) as resp:
                stage = json.loads(resp.read().decode())

            if stage.get("component") != "ak-stage-identification":
                log.warning("Unexpected first stage: %s", stage.get("component"))
                return False

            # Step 2: POST username — expect password challenge
            payload = json.dumps({"uid_field": username}).encode()
            req = self._flow_request(base, data=payload)
            with opener.open(req) as resp:
                stage = json.loads(resp.read().decode())

            if stage.get("component") != "ak-stage-password":
                log.warning("Unexpected second stage: %s", stage.get("component"))
                return False

            # Step 3: POST password — success = redirect, failure = access-denied
            payload = json.dumps({"password": password}).encode()
            req = self._flow_request(base, data=payload)
            with opener.open(req) as resp:
                stage = json.loads(resp.read().decode())

            component = stage.get("component", "")
            if component == "xak-flow-redirect" or stage.get("type") == "redirect":
                return True
            if component == "ak-stage-access-denied":
                return False

            log.warning("Unexpected final stage: %s", component)
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
