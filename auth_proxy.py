"""OpenHost auto-login auth-proxy for wg-easy.

Sits between the OpenHost router and wg-easy's web UI (Nuxt server
on 127.0.0.1:51821).  When an authenticated zone owner visits the
wg-easy UI for the first time on a device, this proxy logs them in
to wg-easy automatically using the on-disk admin password and sets
the resulting ``wg-easy`` sealed-session cookie on the browser.
After the cookie is set, the proxy is a near-pass-through;
subsequent requests carry the cookie and reach wg-easy with no
further auth-proxy involvement.

Pattern B1 (HTTP login replay), modeled on openhost-joplin's
auth_proxy.py.

Auth model summary:

  * Anonymous (no zone_auth) → OpenHost router 302's to /login on
    the parent zone before the request reaches us.  We never see
    anonymous traffic on this app.
  * Owner, has ``wg-easy`` session cookie → forward unchanged.
  * Owner, no ``wg-easy`` cookie → call wg-easy's POST /api/session
    with admin credentials, capture the Set-Cookie, send a 302 to
    the same path with the cookie set.
  * ``/_healthz`` → static 200 (so the OpenHost healthcheck doesn't
    depend on wg-easy's Nuxt cold-start).

Defense in depth: ALWAYS strip any client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` before forwarding
upstream.  The OpenHost router stamps the real value fresh on
every request.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"

# wg-easy uses nuxt-auth-utils' useSession() with name='wg-easy'
# (see src/server/utils/session.ts).  The sealed-cookie value is
# a single opaque base64 blob signed by the server's session
# password (persisted in wg-easy's SQLite DB).
WGEASY_SESSION_COOKIE = "wg-easy"

# Hop-by-hop headers (RFC 9110 §7.6.1) plus the framing headers we
# rebuild ourselves at the proxy seam.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

ALWAYS_STRIP_HEADERS = frozenset(
    h.lower() for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# 16 MiB body cap.  wg-easy's API is tiny (peer config CRUD); the
# largest payload is a few-KB QR code SVG or a wg.conf string.
MAX_BODY_BYTES = 16 * 1024 * 1024

# wg-easy login endpoint.  POST JSON {username, password, remember}
# on success: 200 OK + Set-Cookie: wg-easy=<sealed>; HttpOnly; Path=/
WGEASY_LOGIN_PATH = "/api/session"

# Static healthcheck path.  OpenHost's router probes this; we
# answer 200 without touching wg-easy so it stays green even during
# Nuxt cold start.
HEALTHCHECK_PATH = "/_healthz"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_admin_creds(cred_file: str) -> tuple[str, str] | None:
    """Read WGEASY_ADMIN_USERNAME / WGEASY_ADMIN_PASSWORD from
    start.sh's on-disk credentials file.

    Format: ``export NAME='VALUE'`` per line.
    """
    try:
        with open(cred_file, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        return None
    username = password = None
    for line in content.splitlines():
        m = re.match(
            r"^\s*(?:export\s+)?(WGEASY_ADMIN_USERNAME|WGEASY_ADMIN_PASSWORD)\s*=\s*(.*?)\s*$",
            line,
        )
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key == "WGEASY_ADMIN_USERNAME":
            username = val
        elif key == "WGEASY_ADMIN_PASSWORD":
            password = val
    if username and password:
        return username, password
    return None


def _login_to_wgeasy(
    upstream_host: str,
    upstream_port: int,
    username: str,
    password: str,
    forwarded_host: str,
) -> str | None:
    """POST credentials to wg-easy's /api/session and return the
    Set-Cookie header value, or None on failure.
    """
    payload = json.dumps({
        "username": username,
        "password": password,
        "remember": True,
    }).encode("utf-8")
    host_header = forwarded_host or f"{upstream_host}:{upstream_port}"
    conn = None
    try:
        conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=10)
        conn.request(
            "POST",
            WGEASY_LOGIN_PATH,
            body=payload,
            headers={
                "Host": host_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Content-Length": str(len(payload)),
                # wg-easy's Nuxt server-side validation does not check
                # X-Forwarded-Proto explicitly, but cookie 'secure'
                # flag depends on INSECURE env (we set INSECURE=true
                # in the Dockerfile, so cookies will be non-secure
                # and work over the OpenHost router's HTTPS without
                # browser rejecting them).
                "X-Forwarded-Proto": "https",
            },
        )
        resp = conn.getresponse()
        try:
            body = resp.read()
        except (OSError, http.client.HTTPException):
            body = b""
    except (OSError, http.client.HTTPException) as exc:
        log.warning("auto-login: upstream POST %s failed: %s", WGEASY_LOGIN_PATH, exc)
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    if resp.status != 200:
        log.warning(
            "auto-login: wg-easy returned status %d to login attempt "
            "(expected 200); body=%r",
            resp.status,
            body[:200],
        )
        return None

    # wg-easy may return {"status":"TOTP_REQUIRED"} etc. without
    # setting the session cookie.  Bail in that case.
    try:
        parsed_body = json.loads(body)
        if isinstance(parsed_body, dict) and parsed_body.get("status") != "success":
            log.warning(
                "auto-login: wg-easy login returned non-success status: %r",
                parsed_body.get("status"),
            )
            return None
    except (ValueError, TypeError):
        # Non-JSON body — treat as failure since success is documented
        # to be {"status":"success"}.
        log.warning("auto-login: wg-easy login returned non-JSON body: %r", body[:200])
        return None

    set_cookie = resp.getheader("Set-Cookie")
    if not set_cookie:
        log.warning("auto-login: wg-easy 200 response had no Set-Cookie")
        return None
    return set_cookie


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 51821
    cred_file: str = "/data/app_data/wg-easy/admin-credentials.txt"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _serve_healthz(self) -> None:
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "3")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(b"ok\n")
        except OSError:
            pass

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        # Strip the query string before path matching to avoid bypass
        # via ?foo=bar appended to a non-public path.
        path_only = self.path.split("?", 1)[0]

        if path_only == HEALTHCHECK_PATH:
            self._serve_healthz()
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        cookies = _parse_cookie_header(self.headers.get("Cookie"))
        has_wgeasy_session = WGEASY_SESSION_COOKIE in cookies

        accept = self.headers.get("Accept", "")
        is_html_navigation = (
            self.command == "GET"
            and "text/html" in accept.lower()
        )

        # Diagnostic logging: helps debug SSO flow.  Lists cookie NAMES
        # only (not values, which are sensitive).
        log.info(
            "DIAG path=%s owner=%s has_wg_cookie=%s html_nav=%s cookies=%s",
            path_only,
            is_owner,
            has_wgeasy_session,
            is_html_navigation,
            sorted(cookies.keys()),
        )

        if is_owner and not has_wgeasy_session and is_html_navigation:
            if self._maybe_auto_login():
                return

        self._proxy()

    def _maybe_auto_login(self) -> bool:
        creds = _read_admin_creds(self.cred_file)
        if creds is None:
            log.warning(
                "auto-login: credentials file missing or unreadable at %s; "
                "falling through to manual login",
                self.cred_file,
            )
            return False

        username, password = creds
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        set_cookie = _login_to_wgeasy(
            self.upstream_host, self.upstream_port, username, password, forwarded_host
        )
        if set_cookie is None:
            return False

        target_path = self.path or "/"
        parsed = urllib.parse.urlparse(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = "/"

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            self.send_header("Set-Cookie", set_cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during auto-login redirect: %s", exc)
            return False

        log.info(
            "auto-login: minted wg-easy session for owner; redirected to %s",
            target_path,
        )
        return True

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        # wg-easy is happy without X-Forwarded-Proto but cookie-secure
        # flag depends on INSECURE; we set INSECURE=true so cookies
        # work over the OpenHost router's HTTPS termination.
        cleaned_headers.append(("X-Forwarded-Proto", "https"))

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=120
        )
        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001
                    log.debug("upstream.close() raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            # wg-easy returns 500 on /api/client when the WireGuard
            # interface isn't up yet (e.g. during initial setup or if
            # wireguard-go failed).  Return an empty client list so the
            # UI loads instead of showing an opaque error page.
            if upstream.status >= 500 and self.path.rstrip("/") == "/api/client":
                log.info("upstream 500 on /api/client; returning empty list")
                empty = b"[]"
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(empty)))
                    self.end_headers()
                    self.wfile.write(empty)
                except OSError:
                    pass
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 51821)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()
    cred_file = os.environ.get(
        "AUTH_PROXY_CRED_FILE",
        "/data/app_data/wg-easy/admin-credentials.txt",
    )

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.cred_file = cred_file

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (creds=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        cred_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
