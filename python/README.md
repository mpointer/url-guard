# url-guard (Python)

SSRF guard for outbound URLs. This is the Python twin of the
[@mpointer/url-guard npm package](https://www.npmjs.com/package/@mpointer/url-guard): identical
IP-literal grammar, identical classification tables, identical URL rules,
shared vectors decoded by both suites in CI. Zero dependencies.

```
pip install url-guard
```

```python
from url_guard import assert_public_url, assert_public_url_resolved, UnsafeUrlError

url = assert_public_url("https://api.example.com/v1")            # structural check, no DNS
url = assert_public_url_resolved("https://partner.example/feed")  # every resolved address must be public

assert_public_url(
    "http://docling.railway.internal:5001",
    allow_private=True,                              # self-hosted targets on the private network
    allowed_host_suffixes=(".railway.internal",),    # and nothing else
)
assert_public_url(base_url, require_https=True)      # plaintext only to loopback
```

`UnsafeUrlError` subclasses `ValueError` and carries `.reason` (`parse`,
`protocol`, `blocked-host`, `private-address`, `allow-list`, `dns`,
`timeout`), so a call site that already catches `ValueError` around its own
URL check keeps working when it switches.

A URL whose host another client would read differently is rejected as
`parse`: a `\` in the netloc (`requests` ends the host there), a `%` in the
host (urllib3 decodes it), or a non-ASCII netloc. Pass internationalized
hosts IDNA-encoded (`xn--...`).

See the [repository README](https://github.com/mpointer/url-guard) for the
full design: why hostname string matching is not a guard, the encodings
that are canonicalized, what `allow_private` never relaxes, the DNS rules,
and the rebinding window this does not close.
