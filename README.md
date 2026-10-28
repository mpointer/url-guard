# url-guard

SSRF guard for outbound URLs, extracted from two production applications. Canonical IP-literal parsing in every encoding, classification against the private, metadata, link-local, ULA and CGNAT ranges, DNS-resolved validation, an HTTPS rule, a host allow-list, and (in TypeScript) a `fetch` that re-validates every redirect. Zero dependencies. The Python package shares the grammar, the tables and the test vectors.

```
npm install @mpointer/url-guard
pip install url-guard
```

The npm package is scoped because npm treats `url-guard` and an existing `urlguard` as the same name. The PyPI project, the repository and the Python module are plain `url-guard` / `url_guard`.

## What problem this solves

Your server fetches URLs that someone else chose: an admin's LLM base URL, a partner's webhook, an image in a scraped feed, a vendor endpoint from an environment variable. Each of those is a request your server makes on the attacker's behalf, from inside your network, with your credentials attached. The first target is always the cloud metadata endpoint at `169.254.169.254`, which hands over IAM credentials to anyone who can make the instance ask.

Every application grows a guard for this, and every one of them starts as string matching on the hostname. That is not a guard:

| URL | What a string match sees | What it is |
|---|---|---|
| `http://2130706433/` | a number | 127.0.0.1 in decimal |
| `http://0x7f000001/` | hex | 127.0.0.1 |
| `http://0177.0.0.1/` | not `127.` | 127.0.0.1 in octal |
| `http://127.1/` | not four octets | 127.0.0.1 short form |
| `http://[::ffff:169.254.169.254]/` | IPv6 | the metadata endpoint, IPv4-mapped |
| `http://[::169.254.169.254]/` | IPv6 | the metadata endpoint, IPv4-compatible |
| `http://[64:ff9b::10.0.0.5]/` | IPv6 | 10.0.0.5 through NAT64 |
| `http://[fd00:ec2::254]/` | some ULA | the AWS IPv6 metadata endpoint |
| `https://cdn.attacker.example/` | a public name | an A record for 10.0.0.5 |
| `https://cdn.good.example/` | your own allow-listed CDN | a 302 to `http://169.254.169.254/` |

This library was written after a security scan found three different string-matching guards in one application, each a different subset of the same idea, and a fourth in another. It canonicalizes the host the way the OS resolver and the WHATWG URL parser do, so every encoding of an address lands on the same bytes before any rule runs.

## Quick start

```ts
import { assertPublicUrl, assertPublicUrlResolved, safeFetch, UnsafeUrlError } from "@mpointer/url-guard";

// Synchronous, structural: scheme, blocked names, IP literals in every encoding.
const base = assertPublicUrl(settings.llmBaseUrl);

// Plus DNS: every address the name resolves to must be public.
await assertPublicUrlResolved(partner.webhookUrl);

// Fetch with the guard on the first request and on every redirect hop.
const res = await safeFetch(feedImageUrl, {}, { maxRedirects: 2, maxBytes: 5_000_000, timeoutMs: 10_000 });
```

```python
from url_guard import assert_public_url, assert_public_url_resolved, UnsafeUrlError

assert_public_url(settings.llm_base_url)
assert_public_url_resolved(partner.webhook_url)
```

Each check returns the parsed URL (a `URL` in TypeScript, a `urllib.parse.SplitResult` in Python) and throws `UnsafeUrlError` with a `reason`: `parse`, `protocol`, `blocked-host`, `private-address`, `allow-list`, `dns`, `timeout`, and for `safeFetch` `redirect` and `cross-origin`. In Python `UnsafeUrlError` subclasses `ValueError`, so a call site that already catches `ValueError` around its own check keeps working when it switches.

## What is blocked

Always, whatever the options say:

- `169.254.0.0/16` (link-local, which is where the cloud metadata endpoint lives), `100.100.100.200` (Alibaba Cloud metadata), `fd00:ec2::254` (AWS IPv6 metadata), `fe80::/10`, multicast.
- The names `metadata.google.internal`, `metadata.packet.net`, `metadata.tencentyun.com`, `rancher-metadata`.
- Every embedded-IPv4 form (`::ffff:a.b.c.d`, `::a.b.c.d`, `64:ff9b::a.b.c.d`) is unwrapped before any rule runs, so the metadata address stays blocked however it is wrapped.

Unless `allowPrivate` is set:

- Loopback, `0.0.0.0/8`, RFC1918, CGNAT, the test and benchmark nets, reserved, `::1`, `::`, unique-local `fc00::/7`, Teredo.
- `localhost`, and the suffixes `.localhost`, `.local`, `.internal`.

`allowPrivate` exists for genuinely self-hosted destinations (an inference gateway on a VPC address, an Ollama on `localhost` in development). Drive it from operator configuration only. A flag that the same party who writes the URL can also write is no guard at all, and that inversion of trust is exactly how one of the source guards shipped for five months.

## Two more rules for env-driven base URLs

```ts
assertPublicUrl(process.env.ORCHESTRATOR_URL, {
  requireHttps: true,                          // plaintext only to loopback
  allowedHostSuffixes: [".cloud.ibm.com"],     // and only to the vendor
});
```

`requireHttps` rejects `http:` except to loopback (`localhost` or a loopback literal in any encoding), the one plaintext hop that never leaves the machine. `allowedHostSuffixes` restricts the host to listed domains: the host must equal a suffix or end with `"." + suffix`, so `cloud.ibm.com` matches `api.cloud.ibm.com` and not `evilcloud.ibm.com`. Neither rule relaxes the address rules: an allow-list entry of `169.254.169.254` still rejects.

## DNS, and DNS rebinding

`assertPublicUrlResolved` resolves a hostname and requires every returned address to be permitted. One private answer in a multi-record response rejects the URL; a name with both a public and a private record is exactly the shape an attacker wants. A lookup that fails rejects rather than proceeds, and it is bounded (5 s by default; `lookupTimeoutMs` / `lookup_timeout` to change it), because `dns.lookup` has no timeout of its own and a stalled resolver is a way to hold a serverless invocation open.

Between that resolution and the socket your HTTP client opens, the name can be re-resolved to a different address. That is DNS rebinding, and a check that runs before the connection cannot close it. In TypeScript, `guardedLookup` closes it: hand it to the socket layer and the same rules apply to the address actually dialed.

```ts
import { Agent } from "undici"; // the one place you need it; url-guard stays dependency-free
import { guardedLookup, safeFetch } from "@mpointer/url-guard";

const dispatcher = new Agent({ connect: { lookup: guardedLookup() } }); // reuse it across requests
const res = await safeFetch(untrustedUrl, { dispatcher } as RequestInit);
```

The same function works as the `lookup` option of `http.request`, `https.request` or an `http.Agent`. Pass it the same `allowPrivate` you pass the URL check. An IP-literal host never reaches a `lookup`, so keep the URL check as well: `safeFetch` does both.

In Python the window stays open: neither `requests` nor `httpx` has a public hook for the address it connects to. There, treat rebinding as accepted risk for authenticated or token-gated call sites.

## safeFetch (TypeScript)

`safeFetch` applies the resolved check to the first URL and to every redirect target. Redirects are followed manually because the built-in follower re-validates nothing; a `302` is otherwise all it takes to turn a checked public URL into a request at an internal address.

- A cross-origin hop drops `Authorization` and `Cookie`, so a redirect can never walk a bearer token onto a host the caller did not choose.
- `sameOriginRedirects` refuses any hop that leaves the original origin. `isAllowedRedirect` is a per-hop veto for callers whose scope is narrower than an origin (a path-scoped multi-tenant API can `301` from `/tenants/1234/` to `/tenants/9999/` and stay same-origin).
- `maxRedirects` defaults to 3; `0` refuses any.
- `timeoutMs` bounds each hop AND its DNS lookup, and the whole call is capped at `timeoutMs * (maxRedirects + 1)`.
- `maxBytes` is enforced against `Content-Length` and again while streaming, because a declared length is a claim by the same server you do not trust. Over the cap throws `ResponseTooLargeError`.
- A `303`, and a `301`/`302` on `POST`, become a bodiless `GET`, as `fetch` would. A streaming body cannot be replayed across a `307`/`308`, so that case throws instead of silently re-sending nothing.

### Python: no fetch wrapper, by design

Python has no standard `fetch`, and wrapping one client would leave the others unguarded. Use the resolved check and your client's redirect hook. With httpx:

```python
import httpx
from url_guard import assert_public_url_resolved

def guard_redirects(request: httpx.Request) -> None:
    assert_public_url_resolved(str(request.url), lookup_timeout=5)

client = httpx.Client(follow_redirects=True, event_hooks={"request": [guard_redirects]})
client.get(str(assert_public_url_resolved(untrusted_url, lookup_timeout=5).geturl()))
```

The hook runs on every request httpx makes, redirect hops included, so a pivot to an internal address is rejected before it reaches the wire. `assert_public_url_resolved_async` is the twin for async clients.

## Cross-language

The parser, the range tables and the URL rules are deliberately the same in both languages, and both test suites decode `test/vectors.json`: the same twenty-six private literals, five public ones, the seven metadata forms that must stay blocked under `allowPrivate`, and the six encodings of `127.0.0.1`. Cross-language agreement is proven in CI, not asserted in prose.

## Where it came from

Two production guards, one in each language:

- `safe-fetch.ts` in a Next.js application, written after a security scan found three string-matching guards in the same codebase (an LLM base URL validator, an image re-host, a roster connector that followed arbitrary `Link: rel=next` headers). Its review history is in the comments: the `allowPrivate` early return that let the AWS IPv6 metadata literal through, the DNS lookup that ran outside the timeout budget on redirect hops.
- `url_guard.py` in a FastAPI application, where vendor base URLs come from environment variables: the HTTPS rule and the host allow-list.

## What this is not

Not a web application firewall, not a URL reputation service, and in Python not a defense against DNS rebinding (see above). It decides whether a URL names a destination your server should be willing to connect to, and nothing else.

## License

MIT
