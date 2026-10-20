"""Python suite for url_guard. The address vectors in test/vectors.json are
shared with the TypeScript suite; the point of every case is that a
string-matching guard accepts it."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from url_guard import (
    UnsafeUrlError,
    assert_public_url,
    assert_public_url_resolved,
    assert_public_url_resolved_async,
    classify_address,
    is_loopback_address,
    is_private_address,
    is_public_url,
    parse_ip_literal,
)

V = json.loads((Path(__file__).parents[2] / "test" / "vectors.json").read_text())


def reason_of(fn):
    try:
        fn()
    except UnsafeUrlError as err:
        return err.reason
    return None


class TestParseIpLiteral:
    def test_canonicalizes_every_ipv4_encoding(self):
        for form in V["loopbackForms"]:
            parsed = parse_ip_literal(form)
            assert parsed is not None and parsed.family == 4 and parsed.bytes == (127, 0, 0, 1), form

    def test_parses_bracketed_and_compressed_ipv6(self):
        parsed = parse_ip_literal("[::1]")
        assert parsed is not None and parsed.family == 6 and parsed.bytes == (0,) * 15 + (1,)
        assert parse_ip_literal("::ffff:127.0.0.1") == parse_ip_literal("::ffff:7f00:1")
        assert parse_ip_literal("fe80::1%eth0") == parse_ip_literal("fe80::1")

    def test_returns_none_for_names_and_malformed(self):
        for s in V["notIp"]:
            assert parse_ip_literal(s) is None, s
        assert parse_ip_literal("1.2.3.4.5") is None
        assert parse_ip_literal("::1::2") is None
        assert parse_ip_literal("256.1") is None  # 256 cannot be a non-final octet
        assert parse_ip_literal("127.0.0.1.") == parse_ip_literal("127.0.0.1")


class TestClassifyAddress:
    @pytest.mark.parametrize("address,label", V["private"])
    def test_rejects_private(self, address, label):
        assert classify_address(address) is not None, label
        assert is_private_address(address)

    @pytest.mark.parametrize("address", V["public"])
    def test_permits_public(self, address):
        assert classify_address(address) is None

    @pytest.mark.parametrize("address", V["privateAllowed"])
    def test_permits_private_when_allowed(self, address):
        assert classify_address(address, True) is None

    @pytest.mark.parametrize("address,label", V["alwaysBlocked"])
    def test_metadata_and_link_local_stay_blocked_when_allowed(self, address, label):
        assert classify_address(address, True) is not None, label

    def test_non_ip_is_unclassified(self):
        assert classify_address("api.openai.com") is None


class TestLoopback:
    def test_recognizes_every_loopback_form(self):
        for host in ["localhost", "LOCALHOST.", *V["loopbackForms"], "::1", "[::1]", "::ffff:127.0.0.1", "127.200.1.1"]:
            assert is_loopback_address(host), host

    def test_false_for_other_private_and_public(self):
        for host in ["10.0.0.5", "169.254.169.254", "1.1.1.1", "fc00::1", "example.com", "foo.localhost"]:
            assert not is_loopback_address(host), host


class TestAssertPublicUrl:
    def test_accepts_ordinary_endpoints(self):
        for url in V["urls"]["accept"]:
            assert_public_url(url)

    @pytest.mark.parametrize("address,label", V["private"])
    def test_rejects_private_hosts(self, address, label):
        host = f"[{address}]" if ":" in address else address
        assert reason_of(lambda: assert_public_url(f"http://{host}/v1")) == "private-address", label

    def test_rejects_other_schemes(self):
        for url in V["urls"]["rejectScheme"]:
            assert reason_of(lambda: assert_public_url(url)) == "protocol", url

    def test_rejects_internal_hostnames(self):
        for host in V["urls"]["rejectHost"]:
            assert reason_of(lambda: assert_public_url(f"http://{host}/")) == "blocked-host", host

    def test_rejects_unparseable(self):
        assert reason_of(lambda: assert_public_url("not a url")) == "parse"
        assert reason_of(lambda: assert_public_url("")) == "parse"
        assert reason_of(lambda: assert_public_url("http:///path")) == "parse"
        assert reason_of(lambda: assert_public_url("http://example.com:notaport/")) == "parse"

    def test_is_a_value_error_for_existing_callers(self):
        with pytest.raises(ValueError, match="HTTPS"):
            assert_public_url("http://gateway.example.com/mcp", require_https=True)

    def test_allow_private_permits_localhost_but_never_metadata(self):
        assert_public_url("http://localhost:11434", allow_private=True)
        assert_public_url("http://10.0.0.5:11434", allow_private=True)
        assert_public_url("http://[fc00::1]/v1", allow_private=True)
        for url in ["http://metadata.google.internal/", "http://169.254.169.254/", "http://100.100.100.200/", "http://[fe80::1]/"]:
            with pytest.raises(UnsafeUrlError):
                assert_public_url(url, allow_private=True)

    def test_require_https_rejects_plaintext_except_loopback(self):
        assert reason_of(lambda: assert_public_url("http://example.com/path", require_https=True)) == "protocol"
        assert_public_url("https://example.com/path", require_https=True)
        assert_public_url("http://localhost:4444/mcp", require_https=True, allow_private=True)
        assert_public_url("http://127.0.0.1:4444/mcp", require_https=True, allow_private=True)
        assert reason_of(lambda: assert_public_url("http://10.0.0.5/", require_https=True, allow_private=True)) == "protocol"
        assert reason_of(lambda: assert_public_url("https://169.254.169.254/", require_https=True)) == "private-address"

    def test_allowed_host_suffixes(self):
        suffixes = [".cloud.ibm.com", "techzone.ibm.com"]
        assert_public_url("https://api.us-south.watson-orchestrate.cloud.ibm.com/x", allowed_host_suffixes=suffixes)
        assert_public_url("https://cloud.ibm.com/", allowed_host_suffixes=suffixes)
        assert_public_url("https://demo.techzone.ibm.com/", allowed_host_suffixes=suffixes)
        assert_public_url("https://CLOUD.IBM.COM./", allowed_host_suffixes=suffixes)
        assert reason_of(lambda: assert_public_url("https://evil.example.com/x", allowed_host_suffixes=suffixes)) == "allow-list"
        assert reason_of(lambda: assert_public_url("https://evilcloud.ibm.com/", allowed_host_suffixes=suffixes)) == "allow-list"
        assert reason_of(lambda: assert_public_url("https://x.example/", allowed_host_suffixes=[])) == "allow-list"
        with pytest.raises(ValueError, match="allow-list"):
            assert_public_url("https://evil.example.com/x", allowed_host_suffixes=suffixes)

    def test_allow_list_never_overrides_address_rules(self):
        assert reason_of(lambda: assert_public_url("http://169.254.169.254/", allowed_host_suffixes=["169.254.169.254"])) == "private-address"

    def test_the_rmfx_shape(self):
        """Railway-internal plaintext for one allow-listed suffix, HTTPS everywhere else."""
        assert_public_url("http://docling-serve.railway.internal:5001", allowed_host_suffixes=(".railway.internal",), allow_private=True)
        assert reason_of(lambda: assert_public_url("http://docling-serve.railway.internal:5001", allowed_host_suffixes=(".railway.internal",), allow_private=True, require_https=True)) == "protocol"
        assert reason_of(lambda: assert_public_url("http://evil.example.com", allowed_host_suffixes=(".railway.internal",), allow_private=True)) == "allow-list"
        assert reason_of(lambda: assert_public_url("https://169.254.169.254/latest/meta-data/", allow_private=True)) == "private-address"

    def test_is_public_url_and_return_value(self):
        assert is_public_url("https://api.openai.com")
        assert not is_public_url("http://2130706433/")
        assert not is_public_url("not a url")
        url = assert_public_url("https://api.openai.com/v1")
        assert url.hostname == "api.openai.com" and url.path == "/v1"


class TestResolved:
    def test_rejects_name_resolving_privately(self):
        with pytest.raises(UnsafeUrlError, match=r"10\.0\.0\.5"):
            assert_public_url_resolved("https://rebind.example/v1", lookup_host=lambda h: ["10.0.0.5"])

    def test_rejects_when_any_record_is_private(self):
        err = reason_of(lambda: assert_public_url_resolved("https://split.example/v1", lookup_host=lambda h: ["93.184.216.34", "169.254.169.254"]))
        assert err == "private-address"

    def test_accepts_public_only_answer(self):
        url = assert_public_url_resolved("https://good.example/v1", lookup_host=lambda h: ["93.184.216.34", "2606:4700::1111"])
        assert url.hostname == "good.example"

    def test_resolution_failure_rejects(self):
        def boom(h):
            raise OSError("ENOTFOUND")
        assert reason_of(lambda: assert_public_url_resolved("https://nx.example/", lookup_host=boom)) == "dns"
        assert reason_of(lambda: assert_public_url_resolved("https://empty.example/", lookup_host=lambda h: [])) == "dns"

    def test_ip_literal_is_not_resolved(self):
        calls = []
        assert_public_url_resolved("https://1.1.1.1/", lookup_host=lambda h: calls.append(h) or ["1.1.1.1"])
        assert calls == []

    def test_lookup_timeout(self):
        def stall(h):
            time.sleep(1.0)
            return ["93.184.216.34"]
        started = time.monotonic()
        assert reason_of(lambda: assert_public_url_resolved("https://stalled.example/", lookup_host=stall, lookup_timeout=0.05)) == "timeout"
        assert time.monotonic() - started < 0.9

    def test_allow_list_applies_before_resolving(self):
        calls = []
        r = reason_of(lambda: assert_public_url_resolved("https://evil.example/", allowed_host_suffixes=[".good.example"], lookup_host=lambda h: calls.append(h) or ["1.1.1.1"]))
        assert r == "allow-list" and calls == []

    def test_async_variant(self):
        async def main():
            url = await assert_public_url_resolved_async("https://good.example/v1", lookup_host=lambda h: ["93.184.216.34"])
            assert url.hostname == "good.example"

            async def private(h):
                return ["192.168.1.10"]
            with pytest.raises(UnsafeUrlError, match=r"192\.168\.1\.10"):
                await assert_public_url_resolved_async("https://internal.example/", lookup_host=private)

            async def stall(h):
                await asyncio.sleep(1.0)
                return ["1.1.1.1"]
            with pytest.raises(UnsafeUrlError) as excinfo:
                await assert_public_url_resolved_async("https://stalled.example/", lookup_host=stall, lookup_timeout=0.05)
            assert excinfo.value.reason == "timeout"

            await assert_public_url_resolved_async("https://1.1.1.1/", lookup_host=lambda h: (_ for _ in ()).throw(AssertionError("resolved a literal")))
        asyncio.run(main())
