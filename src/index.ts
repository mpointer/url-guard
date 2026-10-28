/**
 * url-guard: SSRF guard for outbound URLs.
 *
 * String matching on a hostname is not a guard. `http://2130706433/`,
 * `http://0x7f000001/`, `http://[::ffff:127.0.0.1]/` and `http://0/` are all
 * loopback and none of them look like it; a DNS name that simply RESOLVES to
 * 10.0.0.5 defeats every string check; and a `302` pivots to whatever the
 * remote host names regardless of what the original URL passed.
 *
 * So: one module. It canonicalizes the host (decimal, hex, octal and
 * short-form IPv4, bracketed IPv6, IPv4-mapped and IPv4-compatible IPv6,
 * NAT64), resolves DNS names, rejects every private/loopback/link-local/ULA/
 * CGNAT/metadata destination, applies an optional HTTPS rule and host
 * allow-list, and, in `safeFetch`, refuses to follow a redirect without
 * re-running the whole check on the new target.
 *
 * DNS rebinding: between the DNS resolution here and the socket `fetch()`
 * opens, the name can be re-resolved to a different address. `safeFetch`
 * alone does not close that window. `guardedLookup` does: handed to the
 * socket layer (undici's `Agent({ connect: { lookup } })` as the `dispatcher`,
 * or `http.request`'s `lookup`), it applies the same rules to the address
 * actually dialed. It stays opt-in because Node exposes undici's `Agent` only
 * through the `undici` package, and this module has no dependencies.
 */

import type { LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';

export type UnsafeUrlReason =
  | 'parse'
  | 'protocol'
  | 'blocked-host'
  | 'private-address'
  | 'allow-list'
  | 'dns'
  | 'redirect'
  | 'cross-origin'
  | 'timeout';

export class UnsafeUrlError extends Error {
  constructor(message: string, public readonly reason: UnsafeUrlReason) {
    super(message);
    this.name = 'UnsafeUrlError';
  }
}

export interface SafeUrlOptions {
  /**
   * Permit loopback / RFC1918 / ULA / CGNAT destinations. For genuinely
   * self-hosted services (an LLM gateway on a VPC-local address, an Ollama
   * on `localhost` in local dev). NEVER relaxes the metadata or link-local
   * blocks; those have no legitimate use as a destination.
   *
   * Drive this from operator-controlled configuration only. A flag the same
   * party who writes the URL can also write is no guard at all.
   */
  allowPrivate?: boolean;
  /**
   * Reject `http:` except to loopback (`localhost` or a loopback literal),
   * the one plaintext hop that never leaves the machine. For env-driven
   * base URLs that must not be downgraded to plaintext by a typo.
   */
  requireHttps?: boolean;
  /**
   * Restrict the host to these domains. The host must equal a suffix (leading
   * dot stripped) or end with `"." + suffix`, so `"cloud.ibm.com"` matches
   * `api.cloud.ibm.com` but not `evilcloud.ibm.com`.
   */
  allowedHostSuffixes?: readonly string[];
  /**
   * DNS resolver override. Production leaves this unset (`node:dns`); tests
   * inject a stub so they can exercise "name resolves to a private address"
   * without a real lookup.
   */
  lookupHost?: (hostname: string) => Promise<string[]>;
  /**
   * Cap on a single DNS lookup (default 5000). `dns.lookup` has no timeout of
   * its own, so without one a hostile or broken resolver stalls for as long
   * as the OS allows. `safeFetch` sets it from `timeoutMs`.
   */
  lookupTimeoutMs?: number;
}

export interface SafeFetchOptions extends SafeUrlOptions {
  /** Redirect hops to follow, each fully re-validated. Default 3; 0 refuses any. */
  maxRedirects?: number;
  /** Reject a redirect that leaves the original origin instead of following it. */
  sameOriginRedirects?: boolean;
  /**
   * Extra per-hop veto, applied after this module's own checks and after
   * `sameOriginRedirects`. Return false to refuse the hop.
   *
   * Origin equality is not always the caller's boundary. A path-scoped
   * multi-tenant API (`https://vendor.com/tenants/1234/...`) can 301 to
   * `/tenants/9999/` and stay same-origin, which keeps `Authorization`
   * attached, so a caller whose scope is narrower than an origin needs to
   * say so.
   */
  isAllowedRedirect?: (next: URL, current: URL) => boolean;
  /**
   * Per-hop timeout in ms (default 15000). A destination the caller does not
   * control can otherwise hold a serverless invocation open until the
   * platform kills it. Combined with any `signal` the caller passes.
   *
   * This ALSO bounds the DNS lookup for each hop, and the whole call is
   * capped at `timeoutMs * (maxRedirects + 1)`: resolution happens before
   * the abort signal exists, so a stalled resolver on each hop of an
   * attacker-chosen redirect chain would otherwise run outside the budget.
   */
  timeoutMs?: number;
  /**
   * Cap on the response body. Enforced against `Content-Length` when the
   * server sends one, and again while streaming when it does not; a declared
   * length is a claim by the same server you do not trust.
   */
  maxBytes?: number;
}

export class ResponseTooLargeError extends Error {
  constructor(public readonly maxBytes: number) {
    super(`Response body exceeds ${maxBytes} bytes`);
    this.name = 'ResponseTooLargeError';
  }
}

/**
 * Hostnames that are never a legitimate destination, whatever `allowPrivate`
 * says. The IP-literal metadata endpoints are additionally covered by the
 * range tables; they are named here so a rejection says "metadata" rather
 * than "link-local".
 */
export const BLOCKED_HOSTNAMES: ReadonlySet<string> = new Set<string>([
  'localhost',
  'metadata.google.internal',
  'metadata.packet.net',
  'metadata.tencentyun.com',
  'rancher-metadata',
]);

/** Suffixes that only ever name something inside the deployment's network. */
export const BLOCKED_HOST_SUFFIXES: readonly string[] = ['.localhost', '.local', '.internal'];

/** Parsed IP literal: `bytes` is big-endian, 4 or 16 long. */
export interface ParsedIp {
  family: 4 | 6;
  bytes: number[];
}

function parseIpv4Part(part: string): number | null {
  if (part === '') return null;
  let value: number;
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
    value = parseInt(part.slice(2), 16);
  } else if (/^0[0-7]+$/.test(part)) {
    value = parseInt(part.slice(1), 8);
  } else if (/^\d+$/.test(part)) {
    value = parseInt(part, 10);
  } else {
    return null;
  }
  return Number.isFinite(value) ? value : null;
}

/**
 * inet_aton-style IPv4 parsing: the same lenient grammar every OS resolver
 * and the WHATWG URL parser accept, which is why `http://2130706433/` and
 * `http://0x7f000001/` are loopback in a browser. A guard that only knows
 * dotted-quad is blind to three quarters of the encodings.
 */
export function parseIpv4(host: string): ParsedIp | null {
  const parts = host.split('.');
  // A trailing dot ("127.0.0.1.") is a valid absolute form; drop the empty tail.
  if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop();
  if (parts.length === 0 || parts.length > 4) return null;

  const values: number[] = [];
  for (const part of parts) {
    const value = parseIpv4Part(part);
    if (value === null) return null;
    values.push(value);
  }

  // Every part but the last is one octet; the last absorbs the remainder.
  const last = values[values.length - 1] ?? 0;
  for (let i = 0; i < values.length - 1; i++) {
    if ((values[i] ?? 0) > 0xff) return null;
  }
  const tailBits = 8 * (4 - (values.length - 1));
  const maxTail = tailBits >= 32 ? 0xffffffff : 2 ** tailBits - 1;
  if (last > maxTail) return null;

  let numeric = last;
  for (let i = 0; i < values.length - 1; i++) {
    numeric += (values[i] ?? 0) * 2 ** (8 * (3 - i));
  }
  return {
    family: 4,
    bytes: [
      Math.floor(numeric / 2 ** 24) & 0xff,
      Math.floor(numeric / 2 ** 16) & 0xff,
      Math.floor(numeric / 2 ** 8) & 0xff,
      numeric & 0xff,
    ],
  };
}

/** IPv6, including `::` compression and a trailing dotted-quad tail. */
export function parseIpv6(host: string): ParsedIp | null {
  if (!host.includes(':')) return null;
  // Strip a zone id ("fe80::1%eth0"): it never changes which range it is in.
  const withoutZone = host.split('%')[0] ?? '';

  const halves = withoutZone.split('::');
  if (halves.length > 2) return null;

  const expand = (segment: string): number[] | null => {
    if (segment === '') return [];
    const groups = segment.split(':');
    const bytes: number[] = [];
    for (let i = 0; i < groups.length; i++) {
      const group = groups[i] ?? '';
      if (i === groups.length - 1 && group.includes('.')) {
        const embedded = parseIpv4(group);
        if (!embedded) return null;
        bytes.push(...embedded.bytes);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      const value = parseInt(group, 16);
      bytes.push((value >> 8) & 0xff, value & 0xff);
    }
    return bytes;
  };

  const head = expand(halves[0] ?? '');
  if (head === null) return null;
  if (halves.length === 1) {
    return head.length === 16 ? { family: 6, bytes: head } : null;
  }
  const tail = expand(halves[1] ?? '');
  if (tail === null) return null;
  const fill = 16 - head.length - tail.length;
  if (fill < 0) return null;
  return { family: 6, bytes: [...head, ...new Array<number>(fill).fill(0), ...tail] };
}

/** Parse a hostname as an IP literal in any encoding, or return null. */
export function parseIpLiteral(host: string): ParsedIp | null {
  let candidate = host.trim();
  if (candidate.startsWith('[') && candidate.endsWith(']')) {
    candidate = candidate.slice(1, -1);
  }
  if (candidate === '') return null;
  return candidate.includes(':') ? parseIpv6(candidate) : parseIpv4(candidate);
}

function inV4Range(bytes: readonly number[], prefix: readonly number[], maskBits: number): boolean {
  for (let bit = 0; bit < maskBits; bit++) {
    const byte = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if (((bytes[byte] ?? 0) & mask) !== ((prefix[byte] ?? 0) & mask)) return false;
  }
  return true;
}

/**
 * Ranges blocked no matter what: metadata, link-local, multicast and
 * reserved. Nothing self-hosted lives on a multicast or a reserved address,
 * so `allowPrivate` has no business opening them (the IPv6 multicast block
 * below was always unconditional; this makes IPv4 match).
 */
const V4_ALWAYS_BLOCKED: ReadonlyArray<[number[], number, string]> = [
  [[169, 254, 0, 0], 16, 'link-local (includes the cloud metadata endpoint)'],
  [[100, 100, 100, 200], 32, 'Alibaba Cloud metadata endpoint'],
  [[224, 0, 0, 0], 4, 'multicast 224.0.0.0/4'],
  [[240, 0, 0, 0], 4, 'reserved 240.0.0.0/4 (includes broadcast)'],
];

/** Ranges blocked unless `allowPrivate`: genuinely internal but sometimes real. */
const V4_PRIVATE: ReadonlyArray<[number[], number, string]> = [
  [[0, 0, 0, 0], 8, '"this network" (0.0.0.0/8)'],
  [[10, 0, 0, 0], 8, 'RFC1918 10.0.0.0/8'],
  [[100, 64, 0, 0], 10, 'CGNAT 100.64.0.0/10'],
  [[127, 0, 0, 0], 8, 'loopback 127.0.0.0/8'],
  [[172, 16, 0, 0], 12, 'RFC1918 172.16.0.0/12'],
  [[192, 0, 0, 0], 24, 'IETF protocol assignments 192.0.0.0/24'],
  [[192, 0, 2, 0], 24, 'TEST-NET-1'],
  [[192, 88, 99, 0], 24, '6to4 relay anycast'],
  [[192, 168, 0, 0], 16, 'RFC1918 192.168.0.0/16'],
  [[198, 18, 0, 0], 15, 'benchmarking 198.18.0.0/15'],
  [[198, 51, 100, 0], 24, 'TEST-NET-2'],
  [[203, 0, 113, 0], 24, 'TEST-NET-3'],
];

function classifyV4(bytes: readonly number[], allowPrivate: boolean): string | null {
  for (const [prefix, bits, label] of V4_ALWAYS_BLOCKED) {
    if (inV4Range(bytes, prefix, bits)) return label;
  }
  if (allowPrivate) return null;
  for (const [prefix, bits, label] of V4_PRIVATE) {
    if (inV4Range(bytes, prefix, bits)) return label;
  }
  return null;
}

/**
 * IPv6 literals blocked no matter what `allowPrivate` says. `fd00:ec2::254`
 * is AWS's IPv6 IMDS address: it sits inside fc00::/7, so under
 * `allowPrivate` the ULA check would wave it through. Metadata is never a
 * destination we mean to reach, so it is named here instead.
 */
const V6_ALWAYS_BLOCKED: ReadonlyArray<[number[], string]> = [
  [
    [0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54],
    'AWS IPv6 instance metadata fd00:ec2::254',
  ],
];

function classifyV6(bytes: readonly number[], allowPrivate: boolean): string | null {
  const b = (i: number): number => bytes[i] ?? 0;
  const isZeroPrefix = (upTo: number) => bytes.slice(0, upTo).every((x) => x === 0);

  for (const [literal, label] of V6_ALWAYS_BLOCKED) {
    if (literal.every((byte, i) => byte === b(i))) return label;
  }

  // Every embedded-IPv4 form is unwrapped BEFORE the `allowPrivate` early
  // return, so `classifyV4`'s always-blocked ranges (metadata, link-local)
  // still apply to the address actually being reached. Getting this order
  // wrong is how `::169.254.169.254` slips past an allowPrivate deployment:
  // it is not IPv4-MAPPED (bytes 10-11 are zero, not 0xffff), so only the
  // IPv4-COMPATIBLE branch catches it.
  //
  // `::` and `::1` are excluded from the compatible branch purely so they
  // keep their own labels below; both are zero-prefixed and would otherwise
  // classify as 0.0.0.0/8.
  const isLoopbackOrUnspecified = isZeroPrefix(15) && b(15) <= 1;
  if (isZeroPrefix(10) && b(10) === 0xff && b(11) === 0xff) {
    // IPv4-mapped ::ffff:a.b.c.d; otherwise ::ffff:127.0.0.1 walks past
    // every v6 range check while being plain loopback.
    return classifyV4(bytes.slice(12), allowPrivate);
  }
  if (b(0) === 0x00 && b(1) === 0x64 && b(2) === 0xff && b(3) === 0x9b && bytes.slice(4, 12).every((x) => x === 0)) {
    // NAT64 well-known prefix 64:ff9b::/96.
    return classifyV4(bytes.slice(12), allowPrivate);
  }
  if (isZeroPrefix(12) && !isLoopbackOrUnspecified) {
    // IPv4-compatible ::a.b.c.d (deprecated, but still parsed).
    return classifyV4(bytes.slice(12), allowPrivate) ?? 'IPv4-compatible IPv6';
  }

  if (b(0) === 0xfe && (b(1) & 0xc0) === 0x80) return 'IPv6 link-local fe80::/10';
  if (b(0) === 0xff) return 'IPv6 multicast ff00::/8';

  if (allowPrivate) return null;

  if (isZeroPrefix(15) && b(15) === 1) return 'IPv6 loopback ::1';
  if (bytes.every((x) => x === 0)) return 'IPv6 unspecified ::';
  if ((b(0) & 0xfe) === 0xfc) return 'IPv6 unique-local fc00::/7';
  if (b(0) === 0x20 && b(1) === 0x01 && b(2) === 0x00 && b(3) === 0x00) {
    return 'Teredo 2001:0000::/32';
  }
  return null;
}

/**
 * Why this address is not a permitted destination, or null if it is fine.
 * Accepts an IP literal in any encoding; returns null for a non-IP string
 * (a DNS name has to be resolved first; see `assertPublicUrlResolved`).
 */
export function classifyAddress(host: string, allowPrivate = false): string | null {
  const parsed = parseIpLiteral(host);
  if (!parsed) return null;
  return parsed.family === 4
    ? classifyV4(parsed.bytes, allowPrivate)
    : classifyV6(parsed.bytes, allowPrivate);
}

/** Convenience predicate over `classifyAddress` for a bare address string. */
export function isPrivateAddress(host: string, allowPrivate = false): boolean {
  return classifyAddress(host, allowPrivate) !== null;
}

/**
 * True for `localhost` and any loopback literal (127/8, `::1`, and the
 * IPv4-mapped form), in any encoding. This is the exemption `requireHttps`
 * grants: a plaintext connection to the same machine.
 */
export function isLoopbackAddress(host: string): boolean {
  const normalized = normalizeHostname(host);
  if (normalized === 'localhost') return true;
  const parsed = parseIpLiteral(normalized);
  if (!parsed) return false;
  const b = (i: number): number => parsed.bytes[i] ?? 0;
  if (parsed.family === 4) return b(0) === 127;
  if (parsed.bytes.slice(0, 15).every((x) => x === 0) && b(15) === 1) return true;
  return parsed.bytes.slice(0, 10).every((x) => x === 0) && b(10) === 0xff && b(11) === 0xff && b(12) === 127;
}

function normalizeHostname(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  // A trailing root dot is the same name ("evil.com." === "evil.com").
  if (host.endsWith('.') && !host.includes(':')) host = host.slice(0, -1);
  return host;
}

function matchesSuffix(host: string, suffix: string): boolean {
  const base = suffix.toLowerCase().replace(/^\.+/, '');
  return base !== '' && (host === base || host.endsWith('.' + base));
}

/**
 * Synchronous structural check: protocol, blocked hostnames, IP literals in
 * every encoding, the HTTPS rule and the host allow-list. Does NOT resolve
 * DNS; use `assertPublicUrlResolved` (or `safeFetch`) wherever an await is
 * available. This variant exists for call sites that build a client
 * synchronously (an SDK constructor taking a base URL).
 */
export function assertPublicUrl(raw: string | URL, opts: SafeUrlOptions = {}): URL {
  let url: URL;
  try {
    url = raw instanceof URL ? raw : new URL(raw);
  } catch {
    throw new UnsafeUrlError(`Invalid URL: ${String(raw)}`, 'parse');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new UnsafeUrlError(
      `Only http/https URLs are allowed. Got "${url.protocol}" from ${url.href}`,
      'protocol',
    );
  }

  const host = normalizeHostname(url.hostname);
  if (host === '') {
    throw new UnsafeUrlError(`URL has no hostname: ${url.href}`, 'parse');
  }
  if (opts.requireHttps && url.protocol !== 'https:' && !isLoopbackAddress(host)) {
    throw new UnsafeUrlError(`non-loopback URLs must use HTTPS: ${url.href}`, 'protocol');
  }
  if (BLOCKED_HOSTNAMES.has(host)) {
    // `localhost` is the one entry that names a genuine self-hosted service.
    // The metadata names stay blocked under `allowPrivate` too.
    if (!(opts.allowPrivate && host === 'localhost')) {
      throw new UnsafeUrlError(`Blocked hostname: ${host}`, 'blocked-host');
    }
  }
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix)) && !opts.allowPrivate) {
    throw new UnsafeUrlError(`Blocked hostname (internal domain): ${host}`, 'blocked-host');
  }

  const reason = classifyAddress(host, opts.allowPrivate ?? false);
  if (reason) {
    throw new UnsafeUrlError(`Blocked address ${host}: ${reason}`, 'private-address');
  }

  if (opts.allowedHostSuffixes !== undefined) {
    if (!opts.allowedHostSuffixes.some((suffix) => matchesSuffix(host, suffix))) {
      throw new UnsafeUrlError(`host "${host}" is not in the allow-list`, 'allow-list');
    }
  }

  return url;
}

/** Boolean-returning variant of `assertPublicUrl`. */
export function isPublicUrl(raw: string | URL, opts: SafeUrlOptions = {}): boolean {
  try {
    assertPublicUrl(raw, opts);
    return true;
  } catch (err) {
    if (err instanceof UnsafeUrlError) return false;
    throw err;
  }
}

/** Default cap on one DNS lookup when the caller sets none. */
const DEFAULT_LOOKUP_TIMEOUT_MS = 5_000;

async function defaultLookupHost(hostname: string): Promise<string[]> {
  // Dynamic so this module stays importable from a bundle that never calls
  // the async path.
  const dns = await import('node:dns/promises');
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

/**
 * `assertPublicUrl` plus DNS: a hostname that is not already an IP literal is
 * resolved, and EVERY returned address must be permitted. One private answer
 * in a multi-record response rejects the URL; a name with both a public and
 * a private A record is exactly the shape an attacker wants.
 */
export async function assertPublicUrlResolved(
  raw: string | URL,
  opts: SafeUrlOptions = {},
): Promise<URL> {
  const url = assertPublicUrl(raw, opts);
  const host = normalizeHostname(url.hostname);

  // Already an IP literal: assertPublicUrl classified it directly.
  if (parseIpLiteral(host)) return url;
  await resolvePublic(host, opts);
  return url;
}

/** Resolve `host` and return its addresses, rejecting if ANY is not permitted. */
async function resolvePublic(host: string, opts: SafeUrlOptions): Promise<string[]> {
  let addresses: string[];
  try {
    const lookup = (opts.lookupHost ?? defaultLookupHost)(host);
    const timeoutMs = opts.lookupTimeoutMs ?? DEFAULT_LOOKUP_TIMEOUT_MS;
    let timer: ReturnType<typeof setTimeout> | undefined;
    addresses = await Promise.race([
      lookup,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new UnsafeUrlError(`DNS lookup for ${host} exceeded ${timeoutMs}ms`, 'timeout')),
          timeoutMs,
        );
        timer.unref?.();
      }),
    ]).finally(() => clearTimeout(timer));
  } catch (err) {
    // A lookup that timed out is its own reason: callers that treat 'dns'
    // as "transient, retry later" must not silently absorb a resolver
    // being used to hold the invocation open.
    if (err instanceof UnsafeUrlError) throw err;
    throw new UnsafeUrlError(
      `Could not resolve ${host}: ${err instanceof Error ? err.message : String(err)}`,
      'dns',
    );
  }
  if (addresses.length === 0) {
    throw new UnsafeUrlError(`Host ${host} resolved to no addresses`, 'dns');
  }
  for (const address of addresses) {
    const reason = classifyAddress(address, opts.allowPrivate ?? false);
    if (reason) {
      throw new UnsafeUrlError(`Host ${host} resolves to ${address}: ${reason}`, 'private-address');
    }
  }
  return addresses;
}

/**
 * A `lookup` for `net.connect`, `http(s).request`/`http(s).Agent`, or undici's
 * `new Agent({ connect: { lookup } })`, that applies the address rules to
 * every address at CONNECT time. This closes DNS rebinding: the address
 * checked is the address dialed, not one from an earlier, separate lookup.
 *
 * An IP-literal host never reaches `lookup`, so keep running
 * `assertPublicUrl` (or `safeFetch`) on the URL; this covers what it cannot.
 */
export function guardedLookup(opts: SafeUrlOptions = {}): LookupFunction {
  return (hostname, options, callback) => {
    resolvePublic(normalizeHostname(hostname), opts).then(
      (all) => {
        const wanted = options.family === 4 || options.family === 6 ? options.family : 0;
        const records = all
          .map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))
          .filter((record) => wanted === 0 || record.family === wanted);
        const first = records[0];
        if (!first) {
          callback(new UnsafeUrlError(`Host ${hostname} has no IPv${wanted} address`, 'dns'), '', 0);
        } else if (options.all) {
          (callback as unknown as (err: null, records: LookupAddress[]) => void)(null, records);
        } else {
          callback(null, first.address, first.family);
        }
      },
      (err: Error) => callback(err, '', 0),
    );
  };
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Per-hop timeout. Long enough for a slow page, short enough that a hostile
 *  destination cannot pin a serverless invocation open. */
const DEFAULT_TIMEOUT_MS = 15_000;

/** A body we can send again on a 307/308 hop. A stream is already consumed. */
function isReplayableBody(body: BodyInit): boolean {
  return (
    typeof body === 'string' ||
    body instanceof URLSearchParams ||
    body instanceof ArrayBuffer ||
    ArrayBuffer.isView(body) ||
    body instanceof Blob
  );
}

/**
 * Enforce `maxBytes` on a response. `Content-Length` is checked first because
 * it costs nothing, then the body is streamed through a counter: a declared
 * length is a claim by the same server we do not trust, and a chunked
 * response declares nothing at all.
 */
function capResponseBody(response: Response, maxBytes: number): Response {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    void response.body?.cancel().catch(() => {});
    throw new ResponseTooLargeError(maxBytes);
  }
  if (!response.body) return response;

  let seen = 0;
  const limiter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength;
      if (seen > maxBytes) {
        controller.error(new ResponseTooLargeError(maxBytes));
        return;
      }
      controller.enqueue(chunk);
    },
  });
  const capped = new Response(response.body.pipeThrough(limiter), {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  // A constructed Response has url "" and redirected false; keep the real ones.
  Object.defineProperty(capped, 'url', { value: response.url });
  Object.defineProperty(capped, 'redirected', { value: response.redirected });
  return capped;
}

/**
 * `fetch` with the guard applied to the initial URL and to every redirect
 * target. Redirects are followed MANUALLY (`redirect: 'manual'`) because the
 * built-in follower re-validates nothing; a `302` is otherwise all it takes
 * to turn a checked public URL into a request at an internal address.
 *
 * A cross-origin hop drops `Authorization` and `Cookie`, so a redirect can
 * never walk a bearer token onto a host the caller did not choose.
 */
export async function safeFetch(
  rawUrl: string | URL,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<Response> {
  const maxRedirects = opts.maxRedirects ?? 3;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // One deadline over the whole call: DNS for every hop plus every fetch.
  // The per-hop signal alone could not enforce this, because resolution
  // happens before the signal is created.
  const deadline = Date.now() + timeoutMs * (maxRedirects + 1);
  const remaining = () => Math.max(0, deadline - Date.now());
  const resolveOpts: SafeUrlOptions = { ...opts, lookupTimeoutMs: Math.min(timeoutMs, remaining() || 1) };

  let current = await assertPublicUrlResolved(rawUrl, resolveOpts);
  const startOrigin = current.origin;

  let method = init.method ?? 'GET';
  let body = init.body;
  let headers = new Headers(init.headers);

  for (let hop = 0; ; hop++) {
    if (remaining() === 0) {
      throw new UnsafeUrlError(
        `Exceeded the overall ${timeoutMs * (maxRedirects + 1)}ms budget for ${startOrigin}`,
        'timeout',
      );
    }
    const hopMs = Math.min(timeoutMs, remaining());
    const timeout = AbortSignal.timeout(hopMs);
    const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    let response: Response;
    try {
      response = await fetch(current, { ...init, method, body: body ?? null, headers, signal, redirect: 'manual' });
    } catch (err) {
      // Only relabel our own deadline; a caller's abort stays the caller's error.
      if (timeout.aborted && !init.signal?.aborted) {
        throw new UnsafeUrlError(`Request to ${current.origin} exceeded ${hopMs}ms`, 'timeout');
      }
      throw err;
    }
    if (!REDIRECT_STATUSES.has(response.status)) {
      return opts.maxBytes === undefined ? response : capResponseBody(response, opts.maxBytes);
    }

    const location = response.headers.get('location');
    // A 3xx with no Location is not a redirect we can follow; hand it back.
    if (!location) {
      return opts.maxBytes === undefined ? response : capResponseBody(response, opts.maxBytes);
    }
    // The Location header is all we need; release the connection before any exit below.
    await response.body?.cancel().catch(() => {});

    if (hop >= maxRedirects) {
      throw new UnsafeUrlError(
        `Refusing to follow more than ${maxRedirects} redirect(s) from ${startOrigin}`,
        'redirect',
      );
    }

    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      throw new UnsafeUrlError(`Redirect to an unparseable location: ${location}`, 'parse');
    }
    if (opts.sameOriginRedirects && next.origin !== startOrigin) {
      throw new UnsafeUrlError(
        `Refusing a cross-origin redirect from ${startOrigin} to ${next.origin}`,
        'cross-origin',
      );
    }
    if (opts.isAllowedRedirect && !opts.isAllowedRedirect(next, current)) {
      throw new UnsafeUrlError(
        `Refusing a redirect the caller's scope does not permit: ${next.href}`,
        'cross-origin',
      );
    }

    if (next.origin !== current.origin) {
      headers = new Headers(headers);
      headers.delete('authorization');
      headers.delete('cookie');
    }
    // Standard fetch semantics: 303, and 301/302 on POST, become a bodiless GET.
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method.toUpperCase() === 'POST')) {
      method = 'GET';
      body = undefined;
      headers.delete('content-type');
      headers.delete('content-length');
    } else if (body != null && !isReplayableBody(body)) {
      // 307/308 preserve the body, but a stream has already been consumed by
      // the first hop. Fail loudly rather than re-sending an empty body.
      throw new UnsafeUrlError(
        `Cannot replay a streaming request body across a ${response.status} redirect to ${next.href}`,
        'redirect',
      );
    }

    current = await assertPublicUrlResolved(next, {
      ...opts,
      lookupTimeoutMs: Math.min(timeoutMs, remaining() || 1),
    });
  }
}
