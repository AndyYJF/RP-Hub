import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import { config } from '../config.js';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.google',
]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_PROXY_REDIRECTS = 5;

function deny(message = 'Proxy target is not allowed') {
  const err = new Error(message);
  err.status = 403;
  throw err;
}

function isPrivateIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIpv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe80')) return true;
  if (lower.startsWith('ff')) return true;
  if (lower.startsWith('2001:db8')) return true;
  if (lower.startsWith('::ffff:')) {
    const mapped = lower.slice('::ffff:'.length);
    if (isIP(mapped) === 4) return isPrivateIpv4(mapped);
  }
  return false;
}

function normalizeHostname(hostname) {
  return String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

function hostnameAllowed(hostname) {
  const lowerHost = normalizeHostname(hostname);
  if (BLOCKED_HOSTNAMES.has(lowerHost)) return false;
  if (lowerHost.endsWith('.localhost') || lowerHost.endsWith('.local') || lowerHost.endsWith('.internal')) {
    return false;
  }
  const ipVersion = isIP(lowerHost);
  if (ipVersion === 4) return !isPrivateIpv4(lowerHost);
  if (ipVersion === 6) return !isPrivateIpv6(lowerHost);
  if (config.proxyAllowedHosts.length) {
    return config.proxyAllowedHosts.some((allowed) => {
      const host = allowed.toLowerCase();
      return lowerHost === host || lowerHost.endsWith(`.${host}`);
    });
  }
  return true;
}

function assertPublicIp(address) {
  const ipVersion = isIP(address);
  if (ipVersion === 4 && !isPrivateIpv4(address)) return;
  if (ipVersion === 6 && !isPrivateIpv6(address)) return;
  deny();
}

async function resolveSafeAddresses(hostname) {
  const host = normalizeHostname(hostname);
  const ipVersion = isIP(host);
  if (ipVersion) {
    assertPublicIp(host);
    return [{ address: host, family: ipVersion }];
  }

  let addresses;
  try {
    addresses = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    const err = new Error('Proxy target hostname cannot be resolved');
    err.status = 400;
    throw err;
  }

  if (!addresses.length) {
    const err = new Error('Proxy target hostname cannot be resolved');
    err.status = 400;
    throw err;
  }

  for (const item of addresses) {
    assertPublicIp(item.address);
  }
  return addresses;
}

/**
 * Validate a URL before server-side proxy usage.
 * Returns normalized href string.
 */
export function assertSafeProxyUrl(raw, baseUrl) {
  let url;
  try {
    url = new URL(String(raw || ''), baseUrl || undefined);
  } catch {
    const err = new Error('Proxy target URL is invalid');
    err.status = 400;
    throw err;
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    const err = new Error('Proxy target URL must use http or https');
    err.status = 400;
    throw err;
  }
  if (!hostnameAllowed(url.hostname)) deny();
  if (url.username || url.password) deny('Proxy target URL must not include credentials');
  return url.href;
}

export async function assertResolvedSafeProxyUrl(raw, baseUrl) {
  const href = assertSafeProxyUrl(raw, baseUrl);
  const url = new URL(href);
  const addresses = await resolveSafeAddresses(url.hostname);
  return { href, url, address: addresses[0] };
}

function toRequestHeaders(headers = {}, url) {
  const result = {};
  const source = headers instanceof Headers
    ? Array.from(headers.entries())
    : Object.entries(headers || {});

  for (const [key, value] of source) {
    if (value === undefined || value === null) continue;
    const lower = key.toLowerCase();
    if (['host', 'connection', 'content-length'].includes(lower)) continue;
    result[key] = value;
  }
  result.Host = url.host;
  return result;
}

function dropSensitiveRedirectHeaders(headers = {}) {
  const result = {};
  const source = headers instanceof Headers
    ? Array.from(headers.entries())
    : Object.entries(headers || {});

  for (const [key, value] of source) {
    const lower = key.toLowerCase();
    if (['authorization', 'cookie', 'proxy-authorization'].includes(lower)) continue;
    result[key] = value;
  }
  return result;
}

function requestOnce(url, address, options = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    const originalHostname = normalizeHostname(url.hostname);
    const req = client.request({
      protocol: url.protocol,
      hostname: address.address,
      family: address.family,
      port: url.port || (isHttps ? 443 : 80),
      path: `${url.pathname || '/'}${url.search || ''}`,
      method: options.method || 'GET',
      headers: toRequestHeaders(options.headers, url),
      servername: isIP(originalHostname) ? undefined : originalHostname,
      timeout: Number(options.timeout || 120000),
    }, (res) => {
      const responseHeaders = new Headers();
      for (const [key, value] of Object.entries(res.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) responseHeaders.append(key, item);
        } else if (value !== undefined) {
          responseHeaders.set(key, String(value));
        }
      }

      const status = res.statusCode || 0;
      const responseBody = [204, 304].includes(status) ? null : Readable.toWeb(res);
      if (!responseBody) res.resume();
      resolve(new Response(responseBody, {
        status,
        statusText: res.statusMessage || '',
        headers: responseHeaders,
      }));
    });

    req.on('timeout', () => req.destroy(new Error('Proxy request timeout')));
    req.on('error', reject);

    if (options.body !== undefined && options.body !== null) {
      req.write(options.body);
    }
    req.end();
  });
}

function redirectOptions(currentUrl, nextUrl, status, options) {
  const next = { ...options };
  const method = String(options.method || 'GET').toUpperCase();
  const shouldSwitchToGet = status === 303 || ((status === 301 || status === 302) && method === 'POST');

  if (shouldSwitchToGet) {
    next.method = 'GET';
    delete next.body;
  }

  if (currentUrl.origin !== nextUrl.origin) {
    next.headers = dropSensitiveRedirectHeaders(next.headers);
  }
  return next;
}

export async function safeProxyFetch(raw, options = {}, fetchOptions = {}) {
  const maxRedirects = Number.isFinite(fetchOptions.maxRedirects)
    ? fetchOptions.maxRedirects
    : MAX_PROXY_REDIRECTS;
  const { href, url, address } = await assertResolvedSafeProxyUrl(raw, fetchOptions.baseUrl);
  const response = await requestOnce(url, address, options);

  if (!REDIRECT_STATUSES.has(response.status)) return response;

  const location = response.headers.get('location');
  if (!location) return response;
  if (maxRedirects <= 0) {
    const err = new Error('Too many proxy redirects');
    err.status = 508;
    throw err;
  }

  await response.body?.cancel?.().catch?.(() => {});
  const nextHref = assertSafeProxyUrl(location, href);
  const nextUrl = new URL(nextHref);
  return safeProxyFetch(nextHref, redirectOptions(url, nextUrl, response.status, options), {
    ...fetchOptions,
    baseUrl: href,
    maxRedirects: maxRedirects - 1,
  });
}
