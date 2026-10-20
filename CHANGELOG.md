# Changelog

Both packages share one version number and one `v*` tag.

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
