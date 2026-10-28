"""url-guard: SSRF guard for outbound URLs.

Python twin of the url-guard npm package. The IP-literal grammar, the
classification tables and the URL rules are kept identical; both suites
decode the same vectors in ``test/vectors.json``.

String matching on a hostname is not a guard. ``http://2130706433/``,
``http://0x7f000001/``, ``http://[::ffff:127.0.0.1]/`` and ``http://0/`` are
all loopback and none of them look like it; a DNS name that simply RESOLVES to
10.0.0.5 defeats every string check; and a 302 pivots to whatever the remote
host names. This module canonicalizes the host (decimal, hex, octal and
short-form IPv4, bracketed IPv6, IPv4-mapped and IPv4-compatible IPv6, NAT64),
classifies it against the private, metadata, link-local, ULA and CGNAT ranges,
and, in :func:`assert_public_url_resolved`, resolves DNS names and requires
EVERY returned address to be permitted.

Known limit, deliberate and documented rather than papered over: between the
DNS resolution here and the socket your HTTP client opens, the name can be
re-resolved to a different address (DNS rebinding). Closing that needs a
client that pins the connection to the validated address. What this module
buys is that a name pointing at an internal host, an IP literal in any
encoding, and (with your client's redirect hook) a redirect pivot are all
rejected outright, which are the three shapes that appear in real findings.
"""
from __future__ import annotations

import asyncio
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FutureTimeout
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Literal, Optional, Sequence, Union
from urllib.parse import SplitResult, urlsplit

__all__ = [
    "UnsafeUrlError",
    "UnsafeUrlReason",
    "ParsedIp",
    "parse_ipv4",
    "parse_ipv6",
    "parse_ip_literal",
    "classify_address",
    "is_private_address",
    "is_loopback_address",
    "assert_public_url",
    "is_public_url",
    "assert_public_url_resolved",
    "assert_public_url_resolved_async",
    "default_lookup_host",
]

UnsafeUrlReason = Literal[
    "parse",
    "protocol",
    "blocked-host",
    "private-address",
    "allow-list",
    "dns",
    "redirect",
    "cross-origin",
    "timeout",
]


class UnsafeUrlError(ValueError):
    """A URL that must not be fetched. ``reason`` is one of :data:`UnsafeUrlReason`.

    Subclasses ``ValueError`` so call sites that already catch ``ValueError``
    around an outbound-URL check keep working unchanged.
    """

    def __init__(self, message: str, reason: UnsafeUrlReason) -> None:
        super().__init__(message)
        self.reason = reason


# Hostnames that are never a legitimate destination, whatever allow_private
# says. The IP-literal metadata endpoints are additionally covered by the
# range tables; they are named here so a rejection says "metadata" rather
# than "link-local".
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "metadata.packet.net",
        "metadata.tencentyun.com",
        "rancher-metadata",
    }
)

# Suffixes that only ever name something inside the deployment's network.
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal")


@dataclass(frozen=True)
class ParsedIp:
    """An IP literal as big-endian bytes: 4 for IPv4, 16 for IPv6."""

    family: int
    bytes: tuple[int, ...]


_HEX_PART = re.compile(r"0[xX][0-9a-fA-F]+")
_OCT_PART = re.compile(r"0[0-7]+")
_DEC_PART = re.compile(r"\d+")
_HEXTET = re.compile(r"[0-9a-fA-F]{1,4}")


def _parse_ipv4_part(part: str) -> Optional[int]:
    if part == "":
        return None
    if _HEX_PART.fullmatch(part):
        return int(part[2:], 16)
    if _OCT_PART.fullmatch(part):
        return int(part[1:], 8)
    if _DEC_PART.fullmatch(part):
        return int(part, 10)
    return None


def parse_ipv4(host: str) -> Optional[ParsedIp]:
    """inet_aton-style IPv4 parsing: the lenient grammar every OS resolver and
    the WHATWG URL parser accept, which is why ``http://2130706433/`` and
    ``http://0x7f000001/`` are loopback in a browser. A guard that only knows
    dotted-quad is blind to three quarters of the encodings."""
    parts = host.split(".")
    # A trailing dot ("127.0.0.1.") is a valid absolute form; drop the empty tail.
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if len(parts) == 0 or len(parts) > 4:
        return None
    values = []
    for part in parts:
        value = _parse_ipv4_part(part)
        if value is None:
            return None
        values.append(value)
    # Every part but the last is one octet; the last absorbs the remainder.
    for value in values[:-1]:
        if value > 0xFF:
            return None
    tail_bits = 8 * (4 - (len(values) - 1))
    max_tail = 0xFFFFFFFF if tail_bits >= 32 else 2**tail_bits - 1
    if values[-1] > max_tail:
        return None
    numeric = values[-1]
    for i, value in enumerate(values[:-1]):
        numeric += value * 2 ** (8 * (3 - i))
    return ParsedIp(4, tuple((numeric >> shift) & 0xFF for shift in (24, 16, 8, 0)))


def parse_ipv6(host: str) -> Optional[ParsedIp]:
    """IPv6, including ``::`` compression and a trailing dotted-quad tail."""
    if ":" not in host:
        return None
    # Strip a zone id ("fe80::1%eth0"): it never changes which range it is in.
    without_zone = host.split("%")[0]
    halves = without_zone.split("::")
    if len(halves) > 2:
        return None

    def expand(segment: str) -> Optional[list[int]]:
        if segment == "":
            return []
        groups = segment.split(":")
        out: list[int] = []
        for i, group in enumerate(groups):
            if i == len(groups) - 1 and "." in group:
                embedded = parse_ipv4(group)
                if embedded is None:
                    return None
                out.extend(embedded.bytes)
                continue
            if not _HEXTET.fullmatch(group):
                return None
            value = int(group, 16)
            out.extend(((value >> 8) & 0xFF, value & 0xFF))
        return out

    head = expand(halves[0])
    if head is None:
        return None
    if len(halves) == 1:
        return ParsedIp(6, tuple(head)) if len(head) == 16 else None
    tail = expand(halves[1])
    if tail is None:
        return None
    fill = 16 - len(head) - len(tail)
    if fill < 0:
        return None
    return ParsedIp(6, tuple(head + [0] * fill + tail))


def parse_ip_literal(host: str) -> Optional[ParsedIp]:
    """Parse a hostname as an IP literal in any encoding, or return None."""
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate == "":
        return None
    return parse_ipv6(candidate) if ":" in candidate else parse_ipv4(candidate)


def _in_v4_range(b: Sequence[int], prefix: Sequence[int], mask_bits: int) -> bool:
    for bit in range(mask_bits):
        byte = bit >> 3
        mask = 0x80 >> (bit & 7)
        if (b[byte] & mask) != (prefix[byte] & mask):
            return False
    return True


# Ranges blocked no matter what: metadata, link-local, multicast and reserved.
# Nothing self-hosted lives on a multicast or a reserved address, so
# allow_private has no business opening them (the IPv6 multicast block was
# always unconditional; this makes IPv4 match).
V4_ALWAYS_BLOCKED: tuple[tuple[tuple[int, ...], int, str], ...] = (
    ((169, 254, 0, 0), 16, "link-local (includes the cloud metadata endpoint)"),
    ((100, 100, 100, 200), 32, "Alibaba Cloud metadata endpoint"),
    ((224, 0, 0, 0), 4, "multicast 224.0.0.0/4"),
    ((240, 0, 0, 0), 4, "reserved 240.0.0.0/4 (includes broadcast)"),
)

# Ranges blocked unless allow_private: genuinely internal but sometimes real.
V4_PRIVATE: tuple[tuple[tuple[int, ...], int, str], ...] = (
    ((0, 0, 0, 0), 8, '"this network" (0.0.0.0/8)'),
    ((10, 0, 0, 0), 8, "RFC1918 10.0.0.0/8"),
    ((100, 64, 0, 0), 10, "CGNAT 100.64.0.0/10"),
    ((127, 0, 0, 0), 8, "loopback 127.0.0.0/8"),
    ((172, 16, 0, 0), 12, "RFC1918 172.16.0.0/12"),
    ((192, 0, 0, 0), 24, "IETF protocol assignments 192.0.0.0/24"),
    ((192, 0, 2, 0), 24, "TEST-NET-1"),
    ((192, 88, 99, 0), 24, "6to4 relay anycast"),
    ((192, 168, 0, 0), 16, "RFC1918 192.168.0.0/16"),
    ((198, 18, 0, 0), 15, "benchmarking 198.18.0.0/15"),
    ((198, 51, 100, 0), 24, "TEST-NET-2"),
    ((203, 0, 113, 0), 24, "TEST-NET-3"),
)


def _classify_v4(b: Sequence[int], allow_private: bool) -> Optional[str]:
    for prefix, bits, label in V4_ALWAYS_BLOCKED:
        if _in_v4_range(b, prefix, bits):
            return label
    if allow_private:
        return None
    for prefix, bits, label in V4_PRIVATE:
        if _in_v4_range(b, prefix, bits):
            return label
    return None


# IPv6 literals blocked no matter what allow_private says. fd00:ec2::254 is
# AWS's IPv6 IMDS address: it sits inside fc00::/7, so under allow_private the
# ULA check would wave it through. Metadata is never a destination we mean to
# reach, so it is named here instead.
V6_ALWAYS_BLOCKED: tuple[tuple[tuple[int, ...], str], ...] = (
    ((0xFD, 0x00, 0x0E, 0xC2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54), "AWS IPv6 instance metadata fd00:ec2::254"),
)


def _classify_v6(b: Sequence[int], allow_private: bool) -> Optional[str]:
    def zero_prefix(up_to: int) -> bool:
        return all(x == 0 for x in b[:up_to])

    for literal, label in V6_ALWAYS_BLOCKED:
        if all(x == y for x, y in zip(literal, b)):
            return label

    # Every embedded-IPv4 form is unwrapped BEFORE the allow_private early
    # return, so the always-blocked v4 ranges (metadata, link-local) still
    # apply to the address actually being reached. Getting this order wrong
    # is how ::169.254.169.254 slips past an allow_private deployment: it is
    # not IPv4-MAPPED (bytes 10-11 are zero, not 0xffff), so only the
    # IPv4-COMPATIBLE branch catches it.
    #
    # :: and ::1 are excluded from the compatible branch purely so they keep
    # their own labels below; both are zero-prefixed and would otherwise
    # classify as 0.0.0.0/8.
    loopback_or_unspecified = zero_prefix(15) and b[15] <= 1
    if zero_prefix(10) and b[10] == 0xFF and b[11] == 0xFF:
        # IPv4-mapped ::ffff:a.b.c.d; otherwise ::ffff:127.0.0.1 walks past
        # every v6 range check while being plain loopback.
        return _classify_v4(b[12:], allow_private)
    if b[0] == 0x00 and b[1] == 0x64 and b[2] == 0xFF and b[3] == 0x9B and all(x == 0 for x in b[4:12]):
        # NAT64 well-known prefix 64:ff9b::/96.
        return _classify_v4(b[12:], allow_private)
    if zero_prefix(12) and not loopback_or_unspecified:
        # IPv4-compatible ::a.b.c.d (deprecated, but still parsed).
        return _classify_v4(b[12:], allow_private) or "IPv4-compatible IPv6"

    if b[0] == 0xFE and (b[1] & 0xC0) == 0x80:
        return "IPv6 link-local fe80::/10"
    if b[0] == 0xFF:
        return "IPv6 multicast ff00::/8"

    if allow_private:
        return None

    if zero_prefix(15) and b[15] == 1:
        return "IPv6 loopback ::1"
    if all(x == 0 for x in b):
        return "IPv6 unspecified ::"
    if (b[0] & 0xFE) == 0xFC:
        return "IPv6 unique-local fc00::/7"
    if b[0] == 0x20 and b[1] == 0x01 and b[2] == 0x00 and b[3] == 0x00:
        return "Teredo 2001:0000::/32"
    return None


def classify_address(host: str, allow_private: bool = False) -> Optional[str]:
    """Why this address is not a permitted destination, or None if it is fine.
    Accepts an IP literal in any encoding; returns None for a non-IP string (a
    DNS name has to be resolved first; see :func:`assert_public_url_resolved`)."""
    parsed = parse_ip_literal(host)
    if parsed is None:
        return None
    if parsed.family == 4:
        return _classify_v4(parsed.bytes, allow_private)
    return _classify_v6(parsed.bytes, allow_private)


def is_private_address(host: str, allow_private: bool = False) -> bool:
    """Convenience predicate over :func:`classify_address` for a bare address."""
    return classify_address(host, allow_private) is not None


def is_loopback_address(host: str) -> bool:
    """True for ``localhost`` and any loopback literal (127/8, ::1, and the
    IPv4-mapped form), in any encoding. This is the exemption
    ``require_https`` grants: a plaintext connection to the same machine."""
    normalized = _normalize_hostname(host)
    if normalized == "localhost":
        return True
    parsed = parse_ip_literal(normalized)
    if parsed is None:
        return False
    b = parsed.bytes
    if parsed.family == 4:
        return b[0] == 127
    if all(x == 0 for x in b[:15]) and b[15] == 1:
        return True
    return all(x == 0 for x in b[:10]) and b[10] == 0xFF and b[11] == 0xFF and b[12] == 127


def _normalize_hostname(hostname: str) -> str:
    host = hostname.lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    # A trailing root dot is the same name ("evil.com." == "evil.com").
    if host.endswith(".") and ":" not in host:
        host = host[:-1]
    return host


def _matches_suffix(host: str, suffix: str) -> bool:
    base = suffix.lower().lstrip(".")
    return bool(base) and (host == base or host.endswith("." + base))


def assert_public_url(
    raw: Union[str, SplitResult],
    *,
    allow_private: bool = False,
    allowed_host_suffixes: Optional[Iterable[str]] = None,
    require_https: bool = False,
) -> SplitResult:
    """Synchronous structural check: scheme, blocked hostnames, IP literals in
    every encoding, the HTTPS rule and the host allow-list. Does NOT resolve
    DNS; use :func:`assert_public_url_resolved` wherever a lookup is
    affordable.

    ``allow_private`` permits loopback, RFC1918, ULA and CGNAT destinations for
    genuinely self-hosted services. It NEVER relaxes the metadata or
    link-local blocks. Drive it from operator configuration only: a flag the
    same party who writes the URL can also write is no guard at all.

    ``require_https`` rejects ``http://`` except to loopback (``localhost`` or
    a loopback literal), the one plaintext hop that never leaves the machine.

    ``allowed_host_suffixes`` restricts the host to a list of domains: the
    host must equal a suffix (leading dot stripped) or end with ``"." + it``.
    ``"cloud.ibm.com"`` therefore matches ``api.cloud.ibm.com`` but not
    ``evilcloud.ibm.com``.

    Returns the parsed URL (``urllib.parse.SplitResult``).
    """
    try:
        url = raw if isinstance(raw, SplitResult) else urlsplit(raw)
    except ValueError as err:  # e.g. an unclosed or non-IP "[...]" host
        raise UnsafeUrlError(f"Invalid URL: {raw!s} ({err})", "parse") from None
    if not url.scheme and not url.netloc:
        raise UnsafeUrlError(f"Invalid URL: {raw!s}", "parse")
    if url.scheme not in ("http", "https"):
        raise UnsafeUrlError(
            f'Only http/https URLs are allowed. Got "{url.scheme}:" from {url.geturl()}', "protocol"
        )
    try:
        url.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as err:
        raise UnsafeUrlError(f"Invalid URL: {raw!s} ({err})", "parse") from None

    # Reject netlocs other parsers read differently. urllib3 (requests) ends the
    # authority at "\" and percent-decodes the host, so "http://127.0.0.1\@evil.com/"
    # connects to 127.0.0.1 while urlsplit reports evil.com. Non-ASCII hosts must
    # arrive IDNA-encoded (xn--) so no client normalizes them into something else.
    if "\\" in url.netloc or "%" in (url.hostname or "") or not url.netloc.isascii():
        raise UnsafeUrlError(f"Ambiguous host in URL: {url.geturl()}", "parse")

    host = _normalize_hostname(url.hostname or "")
    if host == "":
        raise UnsafeUrlError(f"URL has no hostname: {url.geturl()}", "parse")

    if require_https and url.scheme != "https" and not is_loopback_address(host):
        raise UnsafeUrlError(f"non-loopback URLs must use HTTPS: {url.geturl()}", "protocol")

    if host in BLOCKED_HOSTNAMES:
        # localhost is the one entry that names a genuine self-hosted
        # service. The metadata names stay blocked under allow_private too.
        if not (allow_private and host == "localhost"):
            raise UnsafeUrlError(f"Blocked hostname: {host}", "blocked-host")
    if not allow_private and any(host.endswith(s) for s in BLOCKED_HOST_SUFFIXES):
        raise UnsafeUrlError(f"Blocked hostname (internal domain): {host}", "blocked-host")

    reason = classify_address(host, allow_private)
    if reason:
        raise UnsafeUrlError(f"Blocked address {host}: {reason}", "private-address")

    if allowed_host_suffixes is not None:
        suffixes = tuple(allowed_host_suffixes)
        if not any(_matches_suffix(host, s) for s in suffixes):
            raise UnsafeUrlError(f"host {host!r} is not in the allow-list", "allow-list")

    return url


def is_public_url(raw: str, **opts: object) -> bool:
    """Boolean-returning variant of :func:`assert_public_url`."""
    try:
        assert_public_url(raw, **opts)  # type: ignore[arg-type]
        return True
    except UnsafeUrlError:
        return False


def default_lookup_host(hostname: str) -> list[str]:
    """Every address the system resolver returns for ``hostname``, in order,
    deduplicated. Raises ``socket.gaierror`` when the name does not resolve."""
    infos = socket.getaddrinfo(hostname, None)
    return list(dict.fromkeys(info[4][0] for info in infos))


def _check_resolved(host: str, addresses: Sequence[str], allow_private: bool) -> None:
    if not addresses:
        raise UnsafeUrlError(f"Host {host} resolved to no addresses", "dns")
    for address in addresses:
        reason = classify_address(address, allow_private)
        if reason:
            raise UnsafeUrlError(f"Host {host} resolves to {address}: {reason}", "private-address")


def assert_public_url_resolved(
    raw: Union[str, SplitResult],
    *,
    lookup_host: Optional[Callable[[str], Sequence[str]]] = None,
    lookup_timeout: Optional[float] = None,
    allow_private: bool = False,
    allowed_host_suffixes: Optional[Iterable[str]] = None,
    require_https: bool = False,
) -> SplitResult:
    """:func:`assert_public_url` plus DNS: a hostname that is not already an
    IP literal is resolved, and EVERY returned address must be permitted. One
    private answer in a multi-record response rejects the URL; a name with
    both a public and a private A record is exactly the shape an attacker
    wants.

    ``lookup_timeout`` (seconds) bounds the lookup. ``socket.getaddrinfo`` has
    no timeout of its own, so the lookup runs on a helper thread and a stall
    raises ``UnsafeUrlError('timeout')``; the thread is abandoned and ends
    when the resolver gives up. Pass ``lookup_host`` to inject a resolver
    (tests, or a client that already caches lookups).
    """
    url = assert_public_url(
        raw, allow_private=allow_private, allowed_host_suffixes=allowed_host_suffixes, require_https=require_https
    )
    host = _normalize_hostname(url.hostname or "")
    if parse_ip_literal(host) is not None:
        return url  # assert_public_url classified the literal already
    lookup = lookup_host or default_lookup_host
    try:
        if lookup_timeout is None:
            addresses = lookup(host)
        else:
            pool = ThreadPoolExecutor(max_workers=1)
            try:
                addresses = pool.submit(lookup, host).result(timeout=lookup_timeout)
            except _FutureTimeout:
                raise UnsafeUrlError(f"DNS lookup for {host} exceeded {lookup_timeout}s", "timeout") from None
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
    except UnsafeUrlError:
        raise
    except Exception as err:  # noqa: BLE001 - any resolver failure is a rejection
        raise UnsafeUrlError(f"Could not resolve {host}: {err}", "dns") from err
    _check_resolved(host, list(addresses), allow_private)
    return url


async def _default_lookup_host_async(hostname: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(hostname, None)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def assert_public_url_resolved_async(
    raw: Union[str, SplitResult],
    *,
    lookup_host: Optional[Callable[[str], Union[Sequence[str], Awaitable[Sequence[str]]]]] = None,
    lookup_timeout: Optional[float] = None,
    allow_private: bool = False,
    allowed_host_suffixes: Optional[Iterable[str]] = None,
    require_https: bool = False,
) -> SplitResult:
    """Async twin of :func:`assert_public_url_resolved` using the event loop's
    resolver. ``lookup_host`` may be a plain or an async callable."""
    url = assert_public_url(
        raw, allow_private=allow_private, allowed_host_suffixes=allowed_host_suffixes, require_https=require_https
    )
    host = _normalize_hostname(url.hostname or "")
    if parse_ip_literal(host) is not None:
        return url

    async def run() -> Sequence[str]:
        if lookup_host is None:
            return await _default_lookup_host_async(host)
        result = lookup_host(host)
        if asyncio.iscoroutine(result) or isinstance(result, Awaitable):
            return await result  # type: ignore[no-any-return]
        return result  # type: ignore[return-value]

    try:
        addresses = await (asyncio.wait_for(run(), lookup_timeout) if lookup_timeout is not None else run())
    except asyncio.TimeoutError:
        raise UnsafeUrlError(f"DNS lookup for {host} exceeded {lookup_timeout}s", "timeout") from None
    except UnsafeUrlError:
        raise
    except Exception as err:  # noqa: BLE001
        raise UnsafeUrlError(f"Could not resolve {host}: {err}", "dns") from err
    _check_resolved(host, list(addresses), allow_private)
    return url
