import { isIP } from 'node:net';
import { config } from '../config.js';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.google',
]);

function deny(message = '不允许访问内网或本地地址') {
  const err = new Error(message);
  err.status = 403;
  throw err;
}

function isPrivateIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isPrivateIpv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe80')) return true;
  if (lower.startsWith('::ffff:')) {
    const mapped = lower.slice('::ffff:'.length);
    if (isIP(mapped) === 4) return isPrivateIpv4(mapped);
  }
  return false;
}

function hostnameAllowed(hostname) {
  const lowerHost = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lowerHost)) return false;
  if (lowerHost.endsWith('.localhost') || lowerHost.endsWith('.local') || lowerHost.endsWith('.internal')) {
    return false;
  }
  const ipVersion = isIP(hostname);
  if (ipVersion === 4) return !isPrivateIpv4(hostname);
  if (ipVersion === 6) return !isPrivateIpv6(hostname);
  if (config.proxyAllowedHosts.length) {
    return config.proxyAllowedHosts.some((allowed) => {
      const host = allowed.toLowerCase();
      return lowerHost === host || lowerHost.endsWith(`.${host}`);
    });
  }
  return true;
}

/**
 * Validate a URL before server-side fetch (proxy / image download).
 * Returns normalized href string.
 */
export function assertSafeProxyUrl(raw, baseUrl) {
  let url;
  try {
    url = new URL(String(raw || ''), baseUrl || undefined);
  } catch {
    const err = new Error('目标 URL 无效');
    err.status = 400;
    throw err;
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    const err = new Error('目标 URL 必须是 http/https');
    err.status = 400;
    throw err;
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (!hostnameAllowed(hostname)) deny();
  if (url.username || url.password) deny('目标 URL 不允许包含认证信息');
  return url.href;
}
