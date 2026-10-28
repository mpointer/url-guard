# Changelog

Both packages share one version number and one `v*` tag. The npm package is `@mpointer/url-guard` (npm rejects `url-guard` as too close to an existing `urlguard`); the PyPI project is `url-guard`.

## 0.1.2 (2026-10-28)

Python (security):

- `assert_public_url` (and so both resolved variants) now rejects a netloc
  that another HTTP client would read differently. `urlsplit` reported
  `http://127.0.0.1\@example.com/` as host `example.com`, so even the
  DNS-resolved check passed, while `requests` (urllib3) ends the host at the
  backslash and connected to 127.0.0.1. urllib3 also percent-decodes the host
  (`%31%32%37.0.0.1`). Rejected now, as reason `parse`: any `\` in the netloc,
  any `%` in the host, and any non-ASCII netloc. **Behavior change:**
  internationalized hosts must be passed IDNA-encoded (`xn--...`). The
  TypeScript package is unaffected, because `new URL()` and `fetch` share one
  parser.
- A URL `urlsplit` itself refuses (`http://[::1`) now raises
  `UnsafeUrlError('parse')` instead of a bare `ValueError`, so `is_public_url`
  returns `False` instead of raising.
- Ships `py.typed`.

TypeScript:

- `safeFetch` raises `UnsafeUrlError('timeout')` when its own per-hop timeout
  fires during the request, as documented, instead of a bare `DOMException`.
  An abort from the caller's own `signal` is passed through unchanged.
- With `maxBytes` set, the returned response keeps its real `url` and
  `redirected` instead of `""` and `false`.
- A redirect response's body is released before every refusal, not only on
  the success path, so a refused hop no longer holds its connection open.
- The DNS lookup timer is cleared when the lookup finishes first.
- `engines.node` is `>=20.3`, the first release with `AbortSignal.any`.

Both: `test/vectors.json` gains URL-level vectors (`urls.rejectAmbiguous`,
plus unambiguous neighbours in `urls.accept`) decoded by both suites, and the
Python suite asserts that urllib3 reads the same host as the guard for every
accepted URL.

## 0.1.1 (2026-10-20)

Both packages:

- IPv4 multicast (224.0.0.0/4) and reserved (240.0.0.0/4, which includes
  broadcast) are now blocked unconditionally, like IPv6 multicast already
  was, instead of being opened by `allowPrivate` / `allow_private`. Nothing
  self-hosted lives there. Found while porting a consumer whose old guard
  rejected them regardless of its private-network allowance.

## 0.1.0 (2026-10-20)

First release, extracted from two production guards that had each grown a
different subset of the same idea:

- `safe-fetch.ts` in Future Me, Answered (the full canonicalizer, DNS-resolved
  check and redirect-revalidating `fetch`, built after a security scan found
  three string-matching guards in one app).
- `url_guard.py` in rmfx (the HTTPS rule and host allow-list for env-driven
  base URLs to vendor APIs).

TypeScript: `parseIpLiteral`, `classifyAddress`, `isPrivateAddress`,
`isLoopbackAddress`, `assertPublicUrl`, `isPublicUrl`,
`assertPublicUrlResolved`, `safeFetch`, `UnsafeUrlError`,
`ResponseTooLargeError`. Options: `allowPrivate`, `requireHttps`,
`allowedHostSuffixes`, `lookupHost`, `lookupTimeoutMs`, and for `safeFetch`
`maxRedirects`, `sameOriginRedirects`, `isAllowedRedirect`, `timeoutMs`,
`maxBytes`.

Python: the same parser, tables and URL rules (`assert_public_url`,
`is_public_url`, `assert_public_url_resolved`,
`assert_public_url_resolved_async`, `classify_address`,
`is_private_address`, `is_loopback_address`, `parse_ip_literal`).
`UnsafeUrlError` subclasses `ValueError`. No fetch wrapper: Python has no
standard fetch, so the README shows the resolved check plus a client-side
redirect hook instead.

Shared `test/vectors.json` decoded by both suites.
