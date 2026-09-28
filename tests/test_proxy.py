"""Tests for calmweb.proxy -- critical proxy handler paths.
"""

from __future__ import annotations

import io
import socket
from unittest.mock import MagicMock

import pytest

from calmweb import config, stats
from calmweb.proxy import BlockProxyHandler, is_revocation_request


def _make_handler(path: str = "example.com:443") -> BlockProxyHandler:
    """Construct a BlockProxyHandler with mocked I/O so we can call
    its methods without a real server/socket pair.
    """
    handler = BlockProxyHandler.__new__(BlockProxyHandler)
    handler.path = path
    handler.command = "CONNECT"
    handler.request_version = "HTTP/1.1"

    # Provide a fake wfile so send_error / send_response can write
    handler.wfile = io.BytesIO()
    handler.rfile = io.BytesIO()

    # Fake connection socket
    handler.connection = MagicMock(spec=socket.socket)

    # Stub header-writing helpers that BaseHTTPRequestHandler normally sets up
    handler.headers = {}
    handler._headers_buffer = []
    handler.responses = {
        200: ("OK", ""),
        403: ("Forbidden", ""),
        502: ("Bad Gateway", ""),
    }
    handler.request = MagicMock()
    handler.client_address = ("127.0.0.1", 12345)
    handler.server = MagicMock()
    handler.close_connection = True
    return handler

class TestExtractHostname:
    def test_http_url(self):
        h = _make_handler()
        assert h._extract_hostname_from_path("http://example.com/path") == "example.com"

    def test_https_url(self):
        h = _make_handler()
        assert h._extract_hostname_from_path("https://foo.bar.com:8443/x") == "foo.bar.com"

    def test_plain_path_returns_none(self):
        h = _make_handler()
        # A bare path with no scheme -- urlparse puts it in path, not hostname
        result = h._extract_hostname_from_path("/just/a/path")
        assert result is None

    def test_empty_string(self):
        h = _make_handler()
        result = h._extract_hostname_from_path("")
        assert result is None

    def test_malformed_url_no_crash(self):
        h = _make_handler()
        # Should not raise, even with garbage
        result = h._extract_hostname_from_path("://broken")
        # Result may vary, but no exception
        assert isinstance(result, (str, type(None)))

class TestAllowedConnectPorts:
    def test_expected_ports_present(self):
        expected = {80, 443, 3478}
        assert expected == BlockProxyHandler.ALLOWED_CONNECT_PORTS

    def test_arbitrary_port_not_in_set(self):
        assert 8443 not in BlockProxyHandler.ALLOWED_CONNECT_PORTS

    def test_sip_ports_not_allowed(self):
        assert 5060 not in BlockProxyHandler.ALLOWED_CONNECT_PORTS
        assert 5061 not in BlockProxyHandler.ALLOWED_CONNECT_PORTS

class TestDoConnect:
    """Verify the three-step decision flow in do_CONNECT:
       1) Whitelist check -- bypass everything if whitelisted
       2) Blocklist check -- 403 if blocked
       3) Port check -- 403 if non-standard port + flag on

    We mock the resolver and _establish_tunnel to avoid real sockets.
    """

    @pytest.fixture(autouse=True)
    def _reset_config(self):
        """Clean config globals before each test."""
        self._orig_resolver = config.current_resolver
        self._orig_block_enabled = config.block_enabled
        self._orig_block_other_ports = config.block_http_other_ports
        config.block_enabled = True
        config.block_http_other_ports = True
        yield
        config.current_resolver = self._orig_resolver
        config.block_enabled = self._orig_block_enabled
        config.block_http_other_ports = self._orig_block_other_ports

    def _run_connect(self, host_port: str, *, whitelisted: bool, blocked: bool):
        """Set up a handler with mocked resolver and call do_CONNECT.

        Returns (handler, tunnel_called, send_error_code).
        """
        handler = _make_handler(host_port)

        tunnel_called = []
        error_codes = []

        handler._establish_tunnel = lambda h, p: tunnel_called.append((h, p))

        def fake_send_error(code, message=None, explain=None):
            error_codes.append(code)

        handler.send_error = fake_send_error
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        resolver = MagicMock()
        resolver.is_whitelisted.return_value = whitelisted
        resolver._is_blocked.return_value = blocked
        resolver.maybe_reload_background = MagicMock()
        config.current_resolver = resolver

        handler.do_CONNECT()
        return handler, tunnel_called, error_codes

    def test_whitelisted_domain_non_standard_port_allowed(self):
        """Whitelisted domain on port 8443 must be ALLOWED."""
        _, tunnel_called, error_codes = self._run_connect(
            "example.com:8443", whitelisted=True, blocked=False
        )
        assert len(tunnel_called) == 1, "Tunnel should have been established"
        assert tunnel_called[0] == ("example.com", 8443)
        assert error_codes == []

    def test_non_whitelisted_non_standard_port_blocked(self):
        """Non-whitelisted domain on port 8443 with
        block_http_other_ports=True must get 403."""
        config.block_http_other_ports = True
        _, tunnel_called, error_codes = self._run_connect(
            "unknown.com:8443", whitelisted=False, blocked=False
        )
        assert tunnel_called == [], "Tunnel should NOT be established"
        assert 403 in error_codes

    def test_non_whitelisted_port_443_allowed(self):
        """Standard port 443 should be allowed for non-whitelisted, non-blocked domains."""
        _, tunnel_called, error_codes = self._run_connect(
            "safe.com:443", whitelisted=False, blocked=False
        )
        assert len(tunnel_called) == 1
        assert error_codes == []

    def test_blocked_domain_gets_403(self):
        """A blocked, non-whitelisted domain must receive a 403."""
        _, tunnel_called, error_codes = self._run_connect(
            "evil.com:443", whitelisted=False, blocked=True
        )
        assert tunnel_called == []
        assert 403 in error_codes

    def test_whitelisted_blocked_domain_still_allowed(self):
        """Whitelist has absolute priority, even if the domain is also blocked."""
        _, tunnel_called, error_codes = self._run_connect(
            "overlap.com:443", whitelisted=True, blocked=True
        )
        assert len(tunnel_called) == 1, "Whitelist should override blocklist"
        assert error_codes == []

    def test_port_check_skipped_when_flag_off(self):
        """When block_http_other_ports is False, non-standard ports are allowed."""
        config.block_http_other_ports = False
        _, tunnel_called, error_codes = self._run_connect(
            "somesite.com:9999", whitelisted=False, blocked=False
        )
        assert len(tunnel_called) == 1
        assert error_codes == []


# ===================================================================
# Authority parsing (IPv6 literals, missing / invalid ports)
# ===================================================================


class TestSplitHostPort:
    @pytest.mark.parametrize(
        "authority,expected",
        [
            ("example.com:8443", ("example.com", 8443)),
            ("example.com", ("example.com", 443)),
            ("[::1]:8080", ("::1", 8080)),
            ("[2001:db8::1]:443", ("2001:db8::1", 443)),
            ("[2001:db8::1]", ("2001:db8::1", 443)),
            ("::1", ("::1", 443)),
        ],
    )
    def test_valid_authorities(self, authority, expected):
        from calmweb.proxy import split_host_port

        assert split_host_port(authority) == expected

    @pytest.mark.parametrize(
        "authority",
        ["", "   ", "[::1", "example.com:notaport", "example.com:0", "example.com:99999"],
    )
    def test_invalid_authorities_are_rejected(self, authority):
        from calmweb.proxy import split_host_port

        assert split_host_port(authority) == (None, None)

    def test_default_port_is_configurable(self):
        from calmweb.proxy import split_host_port

        assert split_host_port("example.com", default_port=80) == ("example.com", 80)


class TestNormalizeHostname:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Example.COM", "example.com"),
            ("example.com.", "example.com"),
            ("  example.com  ", "example.com"),
            ("[2001:DB8::1]", "2001:db8::1"),
            ("", None),
            (None, None),
        ],
    )
    def test_normalisation(self, raw, expected):
        from calmweb.proxy import normalize_hostname

        assert normalize_hostname(raw) == expected


class TestIpv6Connect:
    """An IPv6 CONNECT used to crash the ``split(':')`` parser and slip through."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        original = (config.current_resolver, config.block_enabled, config.block_ip_direct)
        config.block_enabled = True
        config.block_ip_direct = True
        yield
        (config.current_resolver, config.block_enabled, config.block_ip_direct) = original

    def _run(self, path: str, blocked: bool = True):
        handler = _make_handler(path)
        tunnelled: list = []
        errors: list = []
        handler._establish_tunnel = lambda h, p: tunnelled.append((h, p))
        handler.send_error = lambda code, message=None, explain=None: errors.append(code)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        resolver = MagicMock()
        resolver.is_whitelisted.return_value = False
        resolver._is_blocked.return_value = blocked
        resolver.maybe_reload_background = MagicMock()
        config.current_resolver = resolver
        handler.do_CONNECT()
        return tunnelled, errors

    def test_bracketed_ipv6_literal_is_filtered_not_crashed(self):
        tunnelled, errors = self._run("[::1]:8080")
        assert tunnelled == []
        assert 403 in errors

    def test_malformed_authority_is_rejected(self):
        tunnelled, errors = self._run("[::1:8080")
        assert tunnelled == []
        assert 403 in errors


class TestPlaintextTunnelHardening:
    """CONNECT to port 80 carries cleartext HTTP inside the tunnel."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        original = (
            config.current_resolver,
            config.block_enabled,
            config.block_http_traffic,
            config.block_http_other_ports,
        )
        config.block_enabled = True
        config.block_http_traffic = True
        config.block_http_other_ports = True
        yield
        (
            config.current_resolver,
            config.block_enabled,
            config.block_http_traffic,
            config.block_http_other_ports,
        ) = original

    def _run(self, path: str, whitelisted: bool = False):
        handler = _make_handler(path)
        tunnelled: list = []
        errors: list = []
        handler._establish_tunnel = lambda h, p: tunnelled.append((h, p))
        handler.send_error = lambda code, message=None, explain=None: errors.append(code)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()

        resolver = MagicMock()
        resolver.is_whitelisted.return_value = whitelisted
        resolver._is_blocked.return_value = False
        resolver.maybe_reload_background = MagicMock()
        config.current_resolver = resolver
        handler.do_CONNECT()
        return tunnelled, errors

    def test_connect_to_port_80_is_blocked_when_https_is_enforced(self):
        tunnelled, errors = self._run("example.com:80")
        assert tunnelled == []
        assert 403 in errors

    def test_connect_to_port_80_is_allowed_when_http_is_permitted(self):
        config.block_http_traffic = False
        tunnelled, errors = self._run("example.com:80")
        assert tunnelled == [("example.com", 80)]
        assert errors == []

    def test_whitelist_still_wins(self):
        tunnelled, errors = self._run("example.com:80", whitelisted=True)
        assert tunnelled == [("example.com", 80)]
        assert errors == []


class TestUpgradeDetection:
    def _handler_with_headers(self, headers: dict) -> BlockProxyHandler:
        handler = _make_handler("http://example.com/ws")
        handler.command = "GET"
        handler.headers = headers
        return handler

    def test_websocket_handshake_is_detected(self):
        handler = self._handler_with_headers(
            {"Upgrade": "websocket", "Connection": "Upgrade"}
        )
        assert handler._is_upgrade_request() is True

    def test_plain_request_is_not_an_upgrade(self):
        handler = self._handler_with_headers({"Connection": "keep-alive"})
        assert handler._is_upgrade_request() is False

    def test_upgrade_headers_survive_forwarding(self):
        handler = self._handler_with_headers(
            {
                "Host": "example.com",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "abc",
            }
        )
        raw = handler._build_forwarded_request("example.com", 80, "/ws", "http").decode()
        assert "Upgrade: websocket" in raw
        assert "Connection: Upgrade" in raw
        assert "Connection: close" not in raw
        assert "Sec-WebSocket-Key: abc" in raw

    def test_normal_request_closes_the_connection(self):
        handler = self._handler_with_headers({"Host": "example.com", "Proxy-Connection": "keep"})
        raw = handler._build_forwarded_request("example.com", 80, "/", "http").decode()
        assert "Connection: close" in raw
        # hop-by-hop headers must not reach the origin
        assert "Proxy-Connection" not in raw
        # exactly one Host header, and it is ours
        assert raw.count("Host: ") == 1


class TestExpect100:
    def test_proxy_does_not_answer_100_continue_itself(self):
        """The origin server owns the interim response; the proxy stays out of it."""
        handler = _make_handler()
        handler.wfile = io.BytesIO()
        assert handler.handle_expect_100() is True
        assert handler.wfile.getvalue() == b""


class TestMethodCoverage:
    @pytest.mark.parametrize(
        "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"]
    )
    def test_handler_exists(self, method):
        assert callable(getattr(BlockProxyHandler, f"do_{method}"))


class TestBlockReason:
    """The activity log must name the list that actually blocked a domain.

    Reporting a plain "blocklist" for everything sends people hunting through
    their own configuration for an entry that lives in a downloaded list.
    """

    @pytest.fixture(autouse=True)
    def _reset(self):
        original = config.block_ip_direct
        config.block_ip_direct = True
        yield
        config.block_ip_direct = original

    def _resolver_saying(self, source: str):
        resolver = MagicMock()
        resolver.describe.return_value = {"source": source, "blocked": True, "match": ""}
        return resolver

    @pytest.mark.parametrize(
        "source,expected",
        [("downloaded", "blocklist"), ("manual", "manual"), ("ip", "ip")],
    )
    def test_reason_follows_the_source(self, source, expected):
        handler = _make_handler()
        assert handler._block_reason(self._resolver_saying(source), "x.example") == expected

    def test_resolver_without_describe_falls_back(self):
        handler = _make_handler()

        class Old:
            pass

        assert handler._block_reason(Old(), "x.example") == "blocklist"
        assert handler._block_reason(Old(), "192.0.2.7") == "ip"

    def test_direct_ip_fallback_respects_the_setting(self):
        handler = _make_handler()

        class Old:
            pass

        config.block_ip_direct = False
        assert handler._block_reason(Old(), "192.0.2.7") == "blocklist"


class TestUnusualMethods:
    """Verbs outside the everyday set must be filtered, not silently refused.

    ``BaseHTTPRequestHandler`` answers 501 by itself for any verb without a
    ``do_*`` method -- before any CalmWeb code runs -- so the request never
    appears in the log or the activity view and the client just retries.
    Outlook (RPC_IN_DATA / RPC_OUT_DATA) and Office/SharePoint (WebDAV) both
    use such verbs.
    """

    @pytest.mark.parametrize(
        "verb",
        [
            "RPC_IN_DATA",
            "RPC_OUT_DATA",
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "MOVE",
            "COPY",
            "LOCK",
            "UNLOCK",
            "REPORT",
            "SEARCH",
            "SUBSCRIBE",
            "TRACE",
        ],
    )
    def test_verb_is_dispatched(self, verb):
        handler = _make_handler()
        # This is exactly the lookup http.server performs before answering 501.
        assert hasattr(handler, f"do_{verb}")
        assert callable(getattr(handler, f"do_{verb}"))

    def test_unusual_verb_reaches_the_filtering_code(self):
        handler = _make_handler()
        handler.command = "PROPFIND"
        calls = []
        handler._handle_http_method = lambda: calls.append(handler.command)
        handler.do_PROPFIND()
        assert calls == ["PROPFIND"]

    def test_common_verbs_keep_their_own_handler(self):
        handler = _make_handler()
        assert handler.do_GET.__func__ is BlockProxyHandler.do_GET

    @pytest.mark.parametrize("name", ["not_a_method", "_private", "do_", "__deepcopy__"])
    def test_non_method_attributes_still_raise(self, name):
        handler = _make_handler()
        with pytest.raises(AttributeError):
            getattr(handler, name)

    @pytest.mark.parametrize("verb", ["GET\x00", "BAD VERB", "with/slash"])
    def test_malformed_verbs_are_refused(self, verb):
        handler = _make_handler()
        assert not hasattr(handler, f"do_{verb}")


class TestRevocationDetection:
    """CRL / AIA / OCSP fetches must be recognised from the request alone."""

    def _headers(self, **kwargs) -> dict:
        return {k.replace("_", "-").title(): v for k, v in kwargs.items()}

    def test_crl_distribution_point(self):
        assert is_revocation_request("GET", "/pki/mscorp/crl/msitwww2.crl", {})

    def test_aia_issuer_certificate(self):
        assert is_revocation_request("GET", "/pkiops/certs/mspki.crt", {})

    def test_extension_match_ignores_query_string(self):
        assert is_revocation_request("GET", "/crl/root.crl?d=abc", {})

    def test_extension_match_is_case_insensitive(self):
        assert is_revocation_request("HEAD", "/PKI/ROOT.CRL", {})

    def test_ocsp_post(self):
        headers = self._headers(content_type="application/ocsp-request")
        assert is_revocation_request("POST", "/ocsp", headers)

    def test_ocsp_post_with_charset_parameter(self):
        headers = self._headers(content_type="application/ocsp-request; charset=utf-8")
        assert is_revocation_request("POST", "/ocsp", headers)

    def test_ocsp_get_base64_payload(self):
        payload = "MFEwTzBNMEswSTAJBgUrDgMCGgUABBRJzGLXJl52dLJUdOaMDe3Nc0ryzQQU"
        assert is_revocation_request("GET", f"/{payload}", {})

    def test_ocsp_get_percent_encoded_payload(self):
        payload = "MFEwTzBNMEswSTAJBgUrDgMCGgUABBRJzGLXJl52dLJUdOaMDe3Nc0ryzQ%3D%3D"
        assert is_revocation_request("GET", f"/ocsp/{payload}", {})

    def test_cryptoapi_user_agent_is_enough(self):
        headers = self._headers(user_agent="Microsoft-CryptoAPI/10.0")
        assert is_revocation_request("GET", "/anything", headers)

    def test_ordinary_page_is_not_revocation(self):
        assert not is_revocation_request("GET", "/index.html", {})

    def test_short_path_segment_is_not_ocsp(self):
        assert not is_revocation_request("GET", "/Menu", {})

    def test_long_segment_not_starting_with_M_is_not_ocsp(self):
        assert not is_revocation_request("GET", "/" + "a" * 60, {})

    def test_ordinary_post_is_not_revocation(self):
        headers = self._headers(content_type="application/json")
        assert not is_revocation_request("POST", "/api/login", headers)

    def test_unusual_verb_is_not_revocation(self):
        assert not is_revocation_request("RPC_IN_DATA", "/rpc/rpcproxy.dll", {})


class _RevocationHandlerCase:
    """Shared harness: run one cleartext request through the HTTP path."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        original = (
            config.current_resolver,
            config.block_enabled,
            config.block_http_traffic,
            config.allow_revocation_http,
        )
        config.block_enabled = True
        config.block_http_traffic = True
        config.allow_revocation_http = True
        stats.reset()
        yield
        (
            config.current_resolver,
            config.block_enabled,
            config.block_http_traffic,
            config.allow_revocation_http,
        ) = original
        stats.reset()

    def _run(
        self,
        path: str,
        headers: dict | None = None,
        whitelisted: bool = False,
        blocked: bool = False,
    ):
        handler = _make_handler(path)
        handler.command = "GET"
        handler.headers = headers if headers is not None else {}

        forwarded: list = []
        rejected: list = []
        handler._forward_to_remote = lambda host, port, blob: forwarded.append((host, port))
        handler._reject = lambda host, port, reason, tunnel: rejected.append(reason)

        resolver = MagicMock()
        resolver.is_whitelisted.return_value = whitelisted
        resolver._is_blocked.return_value = blocked
        resolver.describe.return_value = {"source": "downloaded"}
        resolver.maybe_reload_background = MagicMock()
        config.current_resolver = resolver

        handler._handle_http_method()
        return forwarded, rejected


class TestRevocationExemption(_RevocationHandlerCase):
    """``block_http_traffic`` must not swallow certificate revocation traffic."""

    def test_crl_over_http_is_forwarded(self):
        forwarded, rejected = self._run("http://crl.microsoft.com/pki/crl/root.crl")
        assert forwarded == [("crl.microsoft.com", 80)]
        assert rejected == []

    def test_ordinary_http_page_is_still_blocked(self):
        forwarded, rejected = self._run("http://example.com/index.html")
        assert forwarded == []
        assert rejected == ["http"]

    def test_blocklist_still_wins_over_the_exemption(self):
        forwarded, rejected = self._run(
            "http://crl.evil.example/pki/root.crl", blocked=True
        )
        assert forwarded == []
        assert rejected == ["blocklist"]

    def test_exemption_can_be_turned_off(self):
        """The only way to switch it off is custom.cfg; there is no GUI toggle."""
        config.allow_revocation_http = False
        forwarded, rejected = self._run("http://crl.microsoft.com/pki/crl/root.crl")
        assert forwarded == []
        assert rejected == ["http"]


class TestRevocationIsRecordedAsASystemEvent(_RevocationHandlerCase):
    """The exception has no switch in the interface, so it must be visible."""

    def test_exempted_request_lands_in_the_system_feed(self):
        self._run("http://crl.microsoft.com/pki/crl/root.crl")

        events = stats.events(kinds=("system",))
        assert [(e.host, e.port, e.reason) for e in events] == [
            ("crl.microsoft.com", 80, "revocation")
        ]

    def test_exempted_request_is_not_counted_as_an_ordinary_allow(self):
        self._run("http://crl.microsoft.com/pki/crl/root.crl")

        assert stats.events(kinds=("allowed",)) == []
        assert stats.snapshot()["allowed"] == 0

    def test_an_ordinary_allow_stays_out_of_the_system_feed(self):
        self._run("http://example.com/page", whitelisted=True)

        assert stats.events(kinds=("system",)) == []
        assert len(stats.events(kinds=("allowed",))) == 1


class TestRevocationWhitelist(_RevocationHandlerCase):
    """The first layer: authorities named in the whitelist need no heuristic."""

    def test_whitelisted_authority_is_forwarded_over_http(self):
        forwarded, rejected = self._run(
            "http://crl.microsoft.com/pki/crl/root.crl", whitelisted=True
        )
        assert forwarded == [("crl.microsoft.com", 80)]
        assert rejected == []

    def test_whitelist_wins_even_with_the_exemption_off(self):
        config.allow_revocation_http = False
        forwarded, rejected = self._run(
            "http://ocsp.digicert.com/",
            headers={"Content-Type": "application/ocsp-request"},
            whitelisted=True,
        )
        assert forwarded == [("ocsp.digicert.com", 80)]
        assert rejected == []

    def test_whitelisted_host_is_an_ordinary_allow(self):
        """No system event: nothing exceptional happened, the host was listed."""
        self._run("http://crl.microsoft.com/pki/crl/root.crl", whitelisted=True)

        assert stats.events(kinds=("system",)) == []
        assert [e.reason for e in stats.events(kinds=("allowed",))] == ["whitelist"]
