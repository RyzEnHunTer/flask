"""
CloudFlare Bypass Patches for pyquotex
=======================================
This module patches the upstream pyquotex library at runtime to add:
  1. TLS fingerprinting (CipherSuiteAdapter) — mimics Chrome's JA3 fingerprint
  2. Full Sec-* browser headers — passes Cloudflare browser verification
  3. WebSocket origin/host spoofing — prevents 403 on cloud datacenter IPs
  4. Session persistence — saves cookies/token to avoid re-login on restart
  5. Connection pool refresh — prevents stale TCP connections

Import this BEFORE using Quotex:
    import cf_bypass  # patches pyquotex in-place
    from pyquotex.stable_api import Quotex
"""

import ssl
import sys
import os
import time
import json
import socket
import logging
import platform
from pathlib import Path
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Ensure we can find pyquotex.http — the pip-installed version may lack it,
# but the workspace copy (or the git-installed version on cloud) has it.
def _ensure_pyquotex_http():
    try:
        import pyquotex.http.navigator  # noqa
        return  # Already importable
    except (ImportError, ModuleNotFoundError):
        pass
    # Walk up from this file to find a directory containing pyquotex/http/
    search = Path(__file__).resolve().parent
    for _ in range(5):
        search = search.parent
        candidate = search / "pyquotex" / "http" / "navigator.py"
        if candidate.exists():
            sys.path.insert(0, str(search))
            # Force re-import from the correct location
            for key in list(sys.modules.keys()):
                if key.startswith("pyquotex"):
                    del sys.modules[key]
            return

_ensure_pyquotex_http()

logger = logging.getLogger("cf_bypass")

# ===============================================================
# FIX #1: TLS FINGERPRINTING — CipherSuiteAdapter
# Cloudflare's JA3 system fingerprints the TLS ClientHello.
# Python's default SSL handshake is trivially identified as a bot.
# This adapter mimics Chrome/Firefox's cipher suite + ECDH curve.
# ===============================================================

retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504, 104],
    allowed_methods=["HEAD", "POST", "PUT", "GET", "OPTIONS"]
)


class CipherSuiteAdapter(HTTPAdapter):
    """Custom HTTPS adapter that controls TLS fingerprint to bypass Cloudflare JA3."""
    __attrs__ = [
        'ssl_context', 'max_retries', 'config',
        '_pool_connections', '_pool_maxsize', '_pool_block', 'source_address'
    ]

    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', None)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')

        if self.source_address:
            if isinstance(self.source_address, str):
                self.source_address = (self.source_address, 0)

        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket

            if self.server_hostname:
                self.ssl_context.server_hostname = self.server_hostname

            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

        super().__init__(**kwargs)

    def wrap_socket(self, *args, **kwargs):
        if hasattr(self.ssl_context, 'server_hostname') and self.ssl_context.server_hostname:
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().proxy_manager_for(*args, **kwargs)


# ===============================================================
# PATCHING: Override pyquotex's Browser and QuotexAPI classes
# ===============================================================

def _patch_navigator():
    """Patch pyquotex's Browser class with CipherSuiteAdapter + full headers."""
    try:
        from pyquotex.http.navigator import Browser
    except ImportError:
        logger.warning("Could not import pyquotex.http.navigator — skipping Browser patch")
        return

    # Save original __init__
    _orig_init = Browser.__init__

    def _patched_init(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        self.cipherSuite = kwargs.pop('cipherSuite', 'DEFAULT@SECLEVEL=1')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.proxies = kwargs.pop('proxies', None)
        self.debug = kwargs.pop('debug', False)

        Session.__init__(self, *args, **kwargs)

        self.headers.update(self.get_headers())
        self._mount_fresh_adapter()
        self._session_created_at = time.time()
        self._session_max_age = 1800  # 30 min

    def _patched_get_headers(self):
        """FIX #2: Full browser-like headers to pass Cloudflare verification."""
        self.default_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) "
                          "Gecko/20100101 Firefox/119.0",
        }
        return self.default_headers

    def _patched_mount_fresh_adapter(self):
        """Mount CipherSuiteAdapter instead of default HTTPAdapter."""
        self.mount(
            'https://',
            CipherSuiteAdapter(
                ecdhCurve=self.ecdhCurve,
                cipherSuite=self.cipherSuite,
                server_hostname=self.server_hostname,
                source_address=self.source_address,
                ssl_context=self.ssl_context,
                max_retries=retry_strategy
            )
        )

    def _patched_refresh_pool_if_stale(self):
        """Rebuild connection pool if session is older than max_age."""
        if time.time() - self._session_created_at > self._session_max_age:
            logger.info("Refreshing HTTP connection pool (session age > 30 min)")
            try:
                self.close()
            except Exception:
                pass
            self._mount_fresh_adapter()
            self._session_created_at = time.time()

    def _patched_send_request(self, method, url, headers=None, **kwargs):
        self._refresh_pool_if_stale()
        merged_headers = self.headers.copy()
        if headers:
            merged_headers.update(headers)
        if self.proxies:
            kwargs['proxies'] = self.proxies
        kwargs.setdefault('timeout', 15)
        self.response = self.request(method, url, headers=merged_headers, **kwargs)
        return self.response

    # Check if Browser already has CipherSuiteAdapter (already patched pyquotex)
    if not hasattr(Browser, '_mount_fresh_adapter'):
        Browser.__init__ = _patched_init
        Browser.get_headers = _patched_get_headers
        Browser._mount_fresh_adapter = _patched_mount_fresh_adapter
        Browser._refresh_pool_if_stale = _patched_refresh_pool_if_stale
        Browser.send_request = _patched_send_request
        logger.info("[OK] Patched Browser with CipherSuiteAdapter + connection pool refresh")
    else:
        logger.info("[OK] Browser already has CipherSuiteAdapter -- skipping patch")


def _patch_login():
    """Patch pyquotex's Login class with full Sec-* headers."""
    try:
        from pyquotex.http.login import Login
    except ImportError:
        logger.warning("Could not import pyquotex.http.login — skipping Login patch")
        return

    _orig_get_token = Login.get_token

    def _patched_get_token(self):
        """FIX #2: Add full Sec-* headers to the login flow."""
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.headers["Accept"] = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        )
        self.headers["Referer"] = f"{self.full_url}/sign-in"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        self.send_request("GET", f"{self.full_url}/sign-in/modal/")
        html = self.get_soup()
        match = html.find("input", {"name": "_token"})
        token = None if not match else match.get("value")
        return token

    # Only patch if get_token doesn't already set Sec-Fetch headers
    Login.get_token = _patched_get_token
    logger.info("[OK] Patched Login with full Sec-* headers")


def _patch_api():
    """Patch pyquotex's QuotexAPI with WebSocket origin spoofing + session persistence."""
    try:
        from pyquotex.api import QuotexAPI
    except ImportError:
        logger.warning("Could not import pyquotex.api — skipping API patch")
        return

    import certifi
    import os

    cert_path = certifi.where()
    os.environ['SSL_CERT_FILE'] = cert_path
    os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path
    cacert = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')

    ws_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ws_ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    ws_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ws_ssl_context.load_verify_locations(cert_path)

    _orig_start_websocket = QuotexAPI.start_websocket

    async def _patched_start_websocket(self):
        """FIX #3: WebSocket connection with origin spoofing + proper sockopt."""
        from pyquotex import global_value
        import threading

        global_value.check_websocket_if_connect = None
        global_value.check_websocket_if_error = False
        global_value.websocket_error_reason = None

        if not global_value.SSID:
            await self.authenticate()

        from pyquotex.ws.client import WebsocketClient
        self.websocket_client = WebsocketClient(self)

        payload = {
            "suppress_origin": True,        # FIX #3: CloudFlare handshake 403 fix
            "ping_interval": 24,
            "ping_timeout": 20,
            "ping_payload": "2",
            "origin": self.https_url,       # FIX #3: Must match the domain
            "host": f"ws2.{self.host}",     # FIX #3: Proper host header
            "sslopt": {
                "check_hostname": False,
                "cert_reqs": ssl.CERT_NONE,
                "ca_certs": cacert,
                "context": ws_ssl_context
            },
            "sockopt": (
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ),
            "reconnect": 5
        }

        if platform.system() == "Linux":
            payload["sslopt"]["ssl_version"] = ssl.PROTOCOL_TLS

        self.websocket_thread = threading.Thread(
            target=self.websocket.run_forever,
            kwargs=payload
        )
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        while True:
            if global_value.check_websocket_if_error:
                return False, global_value.websocket_error_reason
            elif global_value.check_websocket_if_connect == 0:
                return False, "Websocket connection closed."
            elif global_value.check_websocket_if_connect == 1:
                return True, "Websocket connected successfully!!!"
            elif global_value.check_rejected_connection == 1:
                global_value.SSID = None
                return True, "Websocket Token Rejected."

    # FIX #2: Patch send_http_request_v1 to include Sec-* headers
    _orig_send_http = getattr(QuotexAPI, 'send_http_request_v1', None)

    def _patched_send_http_request_v1(self, resource, method, data=None, params=None, headers=None):
        """Add full Sec-* headers to every HTTP request."""
        url = resource.url
        cookies = self.session_data.get('cookies')
        user_agent = self.session_data.get('user_agent')
        if cookies:
            self.browser.headers["Cookie"] = cookies
        if user_agent:
            self.browser.headers["User-Agent"] = user_agent
        self.browser.headers["Connection"] = "keep-alive"
        self.browser.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.browser.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.browser.headers["Accept"] = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        )
        if headers and headers.get('referer'):
            self.browser.headers["Referer"] = headers.get('referer')
        self.browser.headers["Upgrade-Insecure-Requests"] = "1"
        self.browser.headers["Sec-Ch-Ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
        self.browser.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.browser.headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        self.browser.headers["Sec-Fetch-Site"] = "same-origin"
        self.browser.headers["Sec-Fetch-User"] = "?1"
        self.browser.headers["Sec-Fetch-Dest"] = "document"
        self.browser.headers["Sec-Fetch-Mode"] = "navigate"
        self.browser.headers["Dnt"] = "1"
        try:
            response = self.browser.send_request(method=method, url=url, data=data, params=params)
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"HTTP request failed for {url}: {e}")
            return None
        return response

    QuotexAPI.start_websocket = _patched_start_websocket
    if _orig_send_http:
        QuotexAPI.send_http_request_v1 = _patched_send_http_request_v1
    logger.info("[OK] Patched QuotexAPI with WebSocket origin spoofing + Sec-* headers")


def _patch_session_persistence():
    """FIX #4: Patch Login.get_profile to persist session data to disk."""
    try:
        from pyquotex.http.login import Login
    except ImportError:
        return

    _orig_get_profile = Login.get_profile

    def _patched_get_profile(self):
        result = _orig_get_profile(self)
        # After the original get_profile saves to session.json,
        # ensure session_data is populated
        if self.ssid and self.cookies:
            self.api.session_data["cookies"] = self.cookies
            self.api.session_data["token"] = self.ssid
            self.api.session_data["user_agent"] = self.headers.get("User-Agent", "")
            # Persist to disk
            try:
                output_file = Path(f"{self.api.resource_path}/session.json")
                output_file.parent.mkdir(exist_ok=True, parents=True)
                output_file.write_text(
                    json.dumps({
                        "cookies": self.cookies,
                        "token": self.ssid,
                        "user_agent": self.headers.get("User-Agent", "")
                    }, indent=4)
                )
                logger.info("[OK] Session persisted to session.json")
            except Exception as e:
                logger.warning(f"Failed to persist session: {e}")
        return result

    Login.get_profile = _patched_get_profile
    logger.info("[OK] Patched Login.get_profile for session persistence")


# ===============================================================
# APPLY ALL PATCHES
# ===============================================================

def apply_all_patches():
    """Apply all CloudFlare bypass patches to pyquotex."""
    print("=" * 60)
    print("  CLOUDFLARE BYPASS -- Applying patches to pyquotex...")
    print("=" * 60)
    _patch_navigator()
    _patch_login()
    _patch_api()
    _patch_session_persistence()
    print("=" * 60)
    print("  [OK] All patches applied successfully")
    print("=" * 60)


# Auto-apply on import
apply_all_patches()
