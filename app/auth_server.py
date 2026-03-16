"""saslauthd mux protocol replacement.

Listens on a Unix socket, speaks the saslauthd wire protocol, and
authenticates users against authentik's flow executor REST API.
Includes a TTL-based credential cache with size limits and per-user
rate limiting.
"""

import grp
import hmac
import logging
import os
import secrets
import socket
import struct
import sys
import threading
import time

from .authentik_api import AuthentikClient

log = logging.getLogger("auth-server")

# Limits
_MAX_FIELD_BYTES = 1024  # max bytes per saslauthd field (username, password, etc.)
_MAX_CACHE_ENTRIES = 10_000
_RATE_LIMIT_WINDOW = 60  # seconds
_RATE_LIMIT_MAX_FAILURES = 5  # per username per window


class AuthServer:
    """Unix socket server implementing the saslauthd mux protocol."""

    def __init__(
        self,
        socket_path: str,
        client: AuthentikClient,
        flow_slug: str,
        cache_ttl: int = 300,
        socket_group: str = "",
    ) -> None:
        self.socket_path = socket_path
        self.client = client
        self.flow_slug = flow_slug
        self.cache_ttl = cache_ttl
        self.socket_group = socket_group
        # Random key generated once per process — makes cached password
        # hashes useless if memory is dumped after the process exits.
        self._hmac_key = secrets.token_bytes(32)
        # Cache: (username, hmac(password)) -> expiry timestamp
        self._cache: dict[tuple[str, str], float] = {}
        self._cache_lock = threading.Lock()
        # Rate limiting: username -> list of failure timestamps
        self._fail_log: dict[str, list[float]] = {}
        self._fail_lock = threading.Lock()

    def run(self) -> None:
        """Listen on the mux socket and accept connections."""
        # Remove stale socket
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        if self.socket_group:
            try:
                gid = grp.getgrnam(self.socket_group).gr_gid
                os.chown(self.socket_path, -1, gid)
            except (KeyError, OSError) as exc:
                log.warning("Could not set socket group to %s: %s", self.socket_group, exc)
        os.chmod(self.socket_path, 0o660)
        sock.listen(16)

        log.info("Listening on %s", self.socket_path)

        while True:
            conn, _ = sock.accept()
            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            t.start()

    def _handle_client(self, conn: socket.socket) -> None:
        """Read a saslauthd request, authenticate, and respond."""
        try:
            username = self._read_field(conn)
            password = self._read_field(conn)
            _service = self._read_field(conn)
            _realm = self._read_field(conn)

            if not username or not password:
                self._send_response(conn, False, "empty credentials")
                return

            ok = self._check_credentials(username, password)
            if ok:
                self._send_response(conn, True, "OK")
            else:
                self._send_response(conn, False, "NO authentication failed")
        except Exception:
            log.exception("Error handling client")
            try:
                self._send_response(conn, False, "NO internal error")
            except Exception:
                pass
        finally:
            conn.close()

    def _is_rate_limited(self, username: str) -> bool:
        """Check if a username has exceeded the failure rate limit."""
        now = time.time()
        cutoff = now - _RATE_LIMIT_WINDOW
        with self._fail_lock:
            timestamps = self._fail_log.get(username)
            if not timestamps:
                return False
            # Prune old entries
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if not timestamps:
                del self._fail_log[username]
                return False
            return len(timestamps) >= _RATE_LIMIT_MAX_FAILURES

    def _record_failure(self, username: str) -> None:
        """Record an authentication failure for rate limiting."""
        now = time.time()
        with self._fail_lock:
            timestamps = self._fail_log.setdefault(username, [])
            timestamps.append(now)
            # Bound the list
            if len(timestamps) > _RATE_LIMIT_MAX_FAILURES * 2:
                cutoff = now - _RATE_LIMIT_WINDOW
                timestamps[:] = [t for t in timestamps if t > cutoff]

    def _check_credentials(self, username: str, password: str) -> bool:
        """Check cache first, then fall through to authentik flow."""
        if self._is_rate_limited(username):
            log.warning("Rate limited auth attempt for %s", username)
            return False

        pw_hash = hmac.new(self._hmac_key, password.encode(), "sha256").hexdigest()
        cache_key = (username, pw_hash)
        now = time.time()

        with self._cache_lock:
            expiry = self._cache.get(cache_key)
            if expiry is not None and expiry > now:
                log.debug("Cache hit for %s", username)
                return True
            # Remove expired entry
            self._cache.pop(cache_key, None)

        log.debug("Authenticating %s via flow executor", username)
        ok = self.client.authenticate_user(username, password, self.flow_slug)

        if ok and self.cache_ttl > 0:
            with self._cache_lock:
                # Evict oldest entries if cache is full
                if len(self._cache) >= _MAX_CACHE_ENTRIES:
                    self._evict_expired(now)
                if len(self._cache) >= _MAX_CACHE_ENTRIES:
                    oldest_key = min(self._cache, key=self._cache.get)  # type: ignore[arg-type]
                    del self._cache[oldest_key]
                self._cache[cache_key] = now + self.cache_ttl
            log.info("Auth success for %s (cached %ds)", username, self.cache_ttl)
        elif not ok:
            self._record_failure(username)
            log.info("Auth failure for %s", username)

        return ok

    def _evict_expired(self, now: float) -> None:
        """Remove expired cache entries. Caller must hold _cache_lock."""
        expired = [k for k, v in self._cache.items() if v <= now]
        for k in expired:
            del self._cache[k]

    @staticmethod
    def _read_field(conn: socket.socket) -> str:
        """Read a 2-byte big-endian length-prefixed field."""
        length_bytes = _recvall(conn, 2)
        if not length_bytes:
            return ""
        length = struct.unpack("!H", length_bytes)[0]
        if length == 0:
            return ""
        if length > _MAX_FIELD_BYTES:
            raise ValueError(f"Field too large: {length} bytes (max {_MAX_FIELD_BYTES})")
        data = _recvall(conn, length)
        if not data:
            return ""
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _send_response(conn: socket.socket, ok: bool, msg: str) -> None:
        """Send a saslauthd mux response."""
        text = "OK" if ok else msg
        data = text.encode("utf-8")
        conn.sendall(struct.pack("!H", len(data)) + data)


def _recvall(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return bytes()
        buf.extend(chunk)
    return bytes(buf)


def main() -> None:
    """Entry point when run as a standalone script."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    url = os.environ["AUTHENTIK_URL"]
    token = os.environ.get("AUTHENTIK_TOKEN", "")
    verify_tls = os.environ.get("VERIFY_TLS", "true").lower() == "true"
    flow_slug = os.environ.get("AUTHENTIK_AUTH_FLOW_SLUG", "default-authentication-flow")
    cache_ttl = int(os.environ.get("BIND_CACHE_TTL", "300"))
    socket_path = "/var/run/saslauthd/mux"

    socket_group = os.environ.get("SASL_SOCKET_GROUP", "openldap")

    client = AuthentikClient(url, token, verify_tls)
    server = AuthServer(socket_path, client, flow_slug, cache_ttl, socket_group)

    try:
        server.run()
    except KeyboardInterrupt:
        log.info("Shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
