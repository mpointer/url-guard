/**
 * The point of every case here is that a string-matching guard accepts it:
 * `2130706433`, `0x7f000001`, `::ffff:127.0.0.1`, a DNS name resolving to
 * 10.0.0.5, and a 302 to any of the above. The address vectors live in
 * vectors.json and are decoded by the Python suite too.
 */
import { readFileSync } from 'node:fs';
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  assertPublicUrl,
  assertPublicUrlResolved,
  classifyAddress,
  isLoopbackAddress,
  isPrivateAddress,
  isPublicUrl,
  parseIpLiteral,
  ResponseTooLargeError,
  safeFetch,
  UnsafeUrlError,
} from '../src/index.js';

interface Vectors {
  private: Array<[string, string]>;
  public: string[];
  alwaysBlocked: Array<[string, string]>;
  privateAllowed: string[];
  loopbackForms: string[];
  notIp: string[];
  urls: { accept: string[]; rejectScheme: string[]; rejectHost: string[] };
}
const V = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8')) as Vectors;

const reasonOf = (fn: () => unknown): string | undefined => {
  try { fn(); return undefined; } catch (e) { return e instanceof UnsafeUrlError ? e.reason : 'other'; }
};

describe('parseIpLiteral', () => {
  it('canonicalizes every IPv4 encoding to the same bytes', () => {
    for (const form of V.loopbackForms) {
      expect(parseIpLiteral(form), form).toEqual({ family: 4, bytes: [127, 0, 0, 1] });
    }
  });

  it('parses bracketed and compressed IPv6', () => {
    expect(parseIpLiteral('[::1]')).toEqual({ family: 6, bytes: [...new Array<number>(15).fill(0), 1] });
    expect(parseIpLiteral('::ffff:127.0.0.1')).toEqual(parseIpLiteral('::ffff:7f00:1'));
    expect(parseIpLiteral('fe80::1%eth0')).toEqual(parseIpLiteral('fe80::1'));
  });

  it('returns null for a DNS name and for malformed literals', () => {
    for (const s of V.notIp) expect(parseIpLiteral(s), s).toBeNull();
    expect(parseIpLiteral('1.2.3.4.5')).toBeNull();
    expect(parseIpLiteral('::1::2')).toBeNull();
    expect(parseIpLiteral('256.1')).toBeNull(); // 256 cannot be a non-final octet
    expect(parseIpLiteral('127.0.0.1.')).toEqual(parseIpLiteral('127.0.0.1'));
  });
});

describe('classifyAddress', () => {
  it.each(V.private)('rejects %s (%s)', (address) => {
    expect(classifyAddress(address)).not.toBeNull();
    expect(isPrivateAddress(address)).toBe(true);
  });

  it.each(V.public)('permits public address %s', (address) => {
    expect(classifyAddress(address)).toBeNull();
  });

  it.each(V.privateAllowed)('permits %s under allowPrivate', (address) => {
    expect(classifyAddress(address, true)).toBeNull();
  });

  // `allowPrivate` documents itself as never relaxing the metadata or
  // link-local blocks, and two IPv6 forms once escaped it: the AWS IMDS
  // literal (inside fc00::/7, so the ULA check that caught it sat below the
  // allowPrivate early return) and the IPv4-COMPATIBLE embedding of the v4
  // metadata address, which the IPv4-MAPPED branch does not match.
  it.each(V.alwaysBlocked)('still blocks %s (%s) under allowPrivate', (address) => {
    expect(classifyAddress(address, true)).not.toBeNull();
  });
});

describe('isLoopbackAddress', () => {
  it('recognizes localhost and every loopback encoding', () => {
    for (const host of ['localhost', 'LOCALHOST.', ...V.loopbackForms, '::1', '[::1]', '::ffff:127.0.0.1', '127.200.1.1']) {
      expect(isLoopbackAddress(host), host).toBe(true);
    }
  });
  it('is false for other private and for public addresses', () => {
    for (const host of ['10.0.0.5', '169.254.169.254', '1.1.1.1', 'fc00::1', 'example.com', 'foo.localhost']) {
      expect(isLoopbackAddress(host), host).toBe(false);
    }
  });
});

describe('assertPublicUrl', () => {
  it('accepts ordinary https endpoints', () => {
    for (const url of V.urls.accept) {
      expect(() => assertPublicUrl(url), url).not.toThrow();
    }
  });

  it.each(V.private)('rejects a URL whose host is %s (%s)', (address) => {
    const host = address.includes(':') ? `[${address}]` : address;
    expect(reasonOf(() => assertPublicUrl(`http://${host}/v1`)), address).toBe('private-address');
  });

  it('rejects non-http(s) schemes', () => {
    for (const url of V.urls.rejectScheme) {
      expect(reasonOf(() => assertPublicUrl(url)), url).toBe('protocol');
    }
  });

  it('rejects internal hostnames and their trailing-dot form', () => {
    for (const host of V.urls.rejectHost) {
      expect(reasonOf(() => assertPublicUrl(`http://${host}/`)), host).toBe('blocked-host');
    }
  });

  it('rejects unparseable input', () => {
    expect(reasonOf(() => assertPublicUrl('not a url'))).toBe('parse');
    expect(reasonOf(() => assertPublicUrl(''))).toBe('parse');
  });

  it('allows localhost under allowPrivate but never a metadata name', () => {
    expect(() => assertPublicUrl('http://localhost:11434', { allowPrivate: true })).not.toThrow();
    expect(() => assertPublicUrl('http://10.0.0.5:11434', { allowPrivate: true })).not.toThrow();
    expect(() => assertPublicUrl('http://[fc00::1]/v1', { allowPrivate: true })).not.toThrow();
    expect(() => assertPublicUrl('http://metadata.google.internal/', { allowPrivate: true })).toThrow(UnsafeUrlError);
    expect(() => assertPublicUrl('http://169.254.169.254/', { allowPrivate: true })).toThrow(UnsafeUrlError);
    expect(() => assertPublicUrl('http://100.100.100.200/', { allowPrivate: true })).toThrow(UnsafeUrlError);
    expect(() => assertPublicUrl('http://[fe80::1]/', { allowPrivate: true })).toThrow(UnsafeUrlError);
  });

  it('requireHttps rejects plaintext except to loopback', () => {
    expect(reasonOf(() => assertPublicUrl('http://example.com/path', { requireHttps: true }))).toBe('protocol');
    expect(() => assertPublicUrl('https://example.com/path', { requireHttps: true })).not.toThrow();
    expect(() => assertPublicUrl('http://localhost:4444/mcp', { requireHttps: true, allowPrivate: true })).not.toThrow();
    expect(() => assertPublicUrl('http://127.0.0.1:4444/mcp', { requireHttps: true, allowPrivate: true })).not.toThrow();
    // A private but non-loopback host is still plaintext across a network.
    expect(reasonOf(() => assertPublicUrl('http://10.0.0.5/', { requireHttps: true, allowPrivate: true }))).toBe('protocol');
    // The HTTPS rule is checked before the address rule, so a plaintext
    // metadata URL reports the scheme problem; with https it reports the address.
    expect(reasonOf(() => assertPublicUrl('https://169.254.169.254/', { requireHttps: true }))).toBe('private-address');
  });

  it('allowedHostSuffixes restricts the host to listed domains', () => {
    const opts = { allowedHostSuffixes: ['.cloud.ibm.com', 'techzone.ibm.com'] };
    expect(() => assertPublicUrl('https://api.us-south.watson-orchestrate.cloud.ibm.com/x', opts)).not.toThrow();
    expect(() => assertPublicUrl('https://cloud.ibm.com/', opts)).not.toThrow();
    expect(() => assertPublicUrl('https://demo.techzone.ibm.com/', opts)).not.toThrow();
    expect(reasonOf(() => assertPublicUrl('https://evil.example.com/x', opts))).toBe('allow-list');
    expect(reasonOf(() => assertPublicUrl('https://evilcloud.ibm.com/', opts))).toBe('allow-list');
    expect(reasonOf(() => assertPublicUrl('https://CLOUD.IBM.COM./', opts))).toBeUndefined();
    expect(reasonOf(() => assertPublicUrl('https://x.example/', { allowedHostSuffixes: [] }))).toBe('allow-list');
  });

  it('an allow-list never overrides the address rules', () => {
    expect(reasonOf(() => assertPublicUrl('http://169.254.169.254/', { allowedHostSuffixes: ['169.254.169.254'] }))).toBe('private-address');
  });

  it('isPublicUrl mirrors assertPublicUrl without throwing', () => {
    expect(isPublicUrl('https://api.openai.com')).toBe(true);
    expect(isPublicUrl('http://2130706433/')).toBe(false);
    expect(isPublicUrl('not a url')).toBe(false);
  });

  it('returns the parsed URL', () => {
    const u = assertPublicUrl('https://api.openai.com/v1');
    expect(u.origin).toBe('https://api.openai.com');
    expect(u.pathname).toBe('/v1');
  });
});

describe('assertPublicUrlResolved', () => {
  it('rejects a public-looking name that resolves to a private address', async () => {
    await expect(
      assertPublicUrlResolved('https://rebind.example/v1', { lookupHost: async () => ['10.0.0.5'] }),
    ).rejects.toThrow(/10\.0\.0\.5/);
  });

  it('rejects when ANY record in a multi-record answer is private', async () => {
    await expect(
      assertPublicUrlResolved('https://split.example/v1', {
        lookupHost: async () => ['93.184.216.34', '169.254.169.254'],
      }),
    ).rejects.toThrow(UnsafeUrlError);
  });

  it('accepts a name that resolves only to public addresses', async () => {
    const url = await assertPublicUrlResolved('https://good.example/v1', {
      lookupHost: async () => ['93.184.216.34', '2606:4700::1111'],
    });
    expect(url.hostname).toBe('good.example');
  });

  it('rejects rather than proceeds when resolution fails', async () => {
    const err = await assertPublicUrlResolved('https://nx.example/', {
      lookupHost: async () => { throw new Error('ENOTFOUND'); },
    }).catch((e) => e);
    expect(err).toBeInstanceOf(UnsafeUrlError);
    expect((err as UnsafeUrlError).reason).toBe('dns');
  });

  it('rejects an empty answer', async () => {
    const err = await assertPublicUrlResolved('https://empty.example/', { lookupHost: async () => [] }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('dns');
  });

  it('does not resolve an IP literal', async () => {
    const lookupHost = vi.fn();
    await assertPublicUrlResolved('https://1.1.1.1/', { lookupHost });
    expect(lookupHost).not.toHaveBeenCalled();
  });

  it('bounds a stalled lookup when lookupTimeoutMs is set', async () => {
    const err = await assertPublicUrlResolved('https://stalled.example/', {
      lookupTimeoutMs: 20,
      lookupHost: () => new Promise<string[]>(() => {}),
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('timeout');
  });

  it('applies the allow-list before resolving', async () => {
    const lookupHost = vi.fn();
    const err = await assertPublicUrlResolved('https://evil.example/', {
      allowedHostSuffixes: ['.good.example'], lookupHost,
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('allow-list');
    expect(lookupHost).not.toHaveBeenCalled();
  });
});

describe('safeFetch redirect handling', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  const redirectTo = (location: string) => new Response(null, { status: 302, headers: { location } });

  it('refuses a redirect that lands on an internal host', async () => {
    const fetchMock = vi.fn(async () => redirectTo('http://169.254.169.254/latest/meta-data/'));
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      safeFetch('https://images.example/hero.png', {}, { lookupHost: async () => ['93.184.216.34'] }),
    ).rejects.toThrow(UnsafeUrlError);
    // The pivot must never reach the wire: one call for the original URL only.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]![1]).toMatchObject({ redirect: 'manual' });
  });

  it('refuses a redirect to a name that resolves privately', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => redirectTo('https://internal.example/secrets')));
    await expect(
      safeFetch('https://images.example/hero.png', {}, {
        lookupHost: async (host) => (host === 'images.example' ? ['93.184.216.34'] : ['192.168.1.10']),
      }),
    ).rejects.toThrow(/192\.168\.1\.10/);
  });

  it('follows a permitted redirect and returns the final response', async () => {
    const fetchMock = vi.fn(async (url: URL) =>
      String(url) === 'https://images.example/hero.png'
        ? redirectTo('https://cdn.example/hero.png')
        : new Response('ok', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    const res = await safeFetch('https://images.example/hero.png', {}, { lookupHost: async () => ['93.184.216.34'] });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('drops Authorization on a cross-origin hop', async () => {
    const fetchMock = vi.fn(async (url: URL) =>
      String(url).startsWith('https://roster.example')
        ? redirectTo('https://other.example/users')
        : new Response('{}', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);

    await safeFetch('https://roster.example/users', { headers: { authorization: 'Bearer secret' } }, {
      lookupHost: async () => ['93.184.216.34'],
    });
    const firstHeaders = (fetchMock.mock.calls[0]![1] as RequestInit).headers as Headers;
    const secondHeaders = (fetchMock.mock.calls[1]![1] as RequestInit).headers as Headers;
    expect(firstHeaders.get('authorization')).toBe('Bearer secret');
    expect(secondHeaders.get('authorization')).toBeNull();
  });

  it('refuses a cross-origin redirect entirely under sameOriginRedirects', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => redirectTo('https://elsewhere.example/x')));
    const err = await safeFetch('https://roster.example/users', {}, {
      sameOriginRedirects: true, lookupHost: async () => ['93.184.216.34'],
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('cross-origin');
  });

  it('lets isAllowedRedirect veto a same-origin hop', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => redirectTo('https://vendor.example/tenants/9999/users')));
    const err = await safeFetch('https://vendor.example/tenants/1234/users', {}, {
      isAllowedRedirect: (next) => next.pathname.startsWith('/tenants/1234/'),
      lookupHost: async () => ['93.184.216.34'],
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('cross-origin');
  });

  it('refuses any redirect when maxRedirects is 0', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => redirectTo('https://cdn.example/hero.png')));
    const err = await safeFetch('https://images.example/hero.png', {}, {
      maxRedirects: 0, lookupHost: async () => ['93.184.216.34'],
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('redirect');
  });

  it('stops after maxRedirects hops rather than looping', async () => {
    const fetchMock = vi.fn(async () => redirectTo('https://a.example/next'));
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
    await expect(
      safeFetch('https://a.example/start', {}, { maxRedirects: 2, lookupHost: async () => ['93.184.216.34'] }),
    ).rejects.toThrow(UnsafeUrlError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects the initial URL before any request is made', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(safeFetch('http://0x7f000001/v1')).rejects.toThrow(UnsafeUrlError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('turns a 303 into a bodiless GET', async () => {
    const fetchMock = vi.fn(async (url: URL) =>
      String(url).endsWith('/submit')
        ? new Response(null, { status: 303, headers: { location: 'https://a.example/done' } })
        : new Response('done', { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
    await safeFetch('https://a.example/submit', { method: 'POST', body: 'x=1' }, { lookupHost: async () => ['93.184.216.34'] });
    const second = fetchMock.mock.calls[1]![1] as RequestInit;
    expect(second.method).toBe('GET');
    expect(second.body ?? null).toBeNull();
  });

  it('refuses to replay a streaming body across a 307', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, {
      status: 307, headers: { location: 'https://a.example/next' },
    })));
    const body = new ReadableStream({ start(c) { c.close(); } });
    await expect(
      safeFetch('https://a.example/start', { method: 'POST', body, duplex: 'half' } as RequestInit, {
        lookupHost: async () => ['93.184.216.34'],
      }),
    ).rejects.toThrow(/replay a streaming request body/);
  });
});

describe('safeFetch limits', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('bounds a stalled DNS lookup instead of hanging', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const err = await safeFetch('https://stalled.example/', {}, {
      timeoutMs: 30,
      lookupHost: () => new Promise<string[]>(() => {}),
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('timeout');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('bounds a stalled lookup on a REDIRECT hop too, not just the first', async () => {
    let call = 0;
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(null, { status: 302, headers: { location: 'https://second.example/x' } }),
    ));
    const err = await safeFetch('https://first.example/', {}, {
      timeoutMs: 30,
      lookupHost: () => {
        call += 1;
        return call === 1 ? Promise.resolve(['93.184.216.34']) : new Promise<string[]>(() => {});
      },
    }).catch((e) => e);
    expect((err as UnsafeUrlError).reason).toBe('timeout');
  });

  it('applies a per-hop timeout signal', async () => {
    const fetchMock = vi.fn(async () => new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock as unknown as typeof fetch);
    await safeFetch('https://a.example/', {}, { timeoutMs: 1234, lookupHost: async () => ['93.184.216.34'] });
    expect((fetchMock.mock.calls[0]![1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
  });

  it('rejects on a Content-Length over maxBytes without reading the body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('x'.repeat(100), {
      status: 200, headers: { 'content-length': '100' },
    })));
    await expect(
      safeFetch('https://a.example/big', {}, { maxBytes: 10, lookupHost: async () => ['93.184.216.34'] }),
    ).rejects.toThrow(ResponseTooLargeError);
  });

  it('rejects while streaming when the server declares no length', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(64)); controller.close(); },
    });
    vi.stubGlobal('fetch', vi.fn(async () => new Response(stream, { status: 200 })));
    const res = await safeFetch('https://a.example/chunked', {}, { maxBytes: 10, lookupHost: async () => ['93.184.216.34'] });
    await expect(res.arrayBuffer()).rejects.toThrow(ResponseTooLargeError);
  });

  it('passes a body under the cap straight through', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('small', { status: 200 })));
    const res = await safeFetch('https://a.example/ok', {}, { maxBytes: 1024, lookupHost: async () => ['93.184.216.34'] });
    expect(await res.text()).toBe('small');
  });
});
