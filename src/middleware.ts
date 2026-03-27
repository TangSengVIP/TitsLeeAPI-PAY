import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Security headers applied to all responses from sub2apipay.
const SECURITY_HEADERS: Record<string, string> = {
  // Prevent MIME type sniffing
  'X-Content-Type-Options': 'nosniff',
  // Prevent clickjacking (overridden by CSP frame-ancestors where needed)
  'X-Frame-Options': 'DENY',
  // Restrict referrer information in cross-origin requests
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  // Prevent information leakage in browser address bar
  'X-Permitted-Cross-Domain-Policies': 'none',
  // HSTS: enforce HTTPS for 1 year if the request was HTTPS.
  // Operators should extend this header in their reverse proxy/TLS terminator
  // for full preload compliance.
  // 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  // Permissions Policy: disable powerful browser APIs
  'Permissions-Policy': (
    'accelerometer=(), camera=(), document-domain=(), ' +
    'geolocation=(), gyroscope=(), magnetometer=(), microphone=(), ' +
    'payment=(self), speaker=(), sync-xhr=(), usb=()'
  ),
};

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // ── Apply baseline security headers ─────────────────────────────────────
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }

  // ── HSTS: only set on HTTPS requests ────────────────────────────────────
  if (request.headers.get('x-forwarded-proto') === 'https' ||
      request.headers.get('x-url-scheme') === 'https' ||
      request.nextUrl.protocol === 'https:') {
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  // ── Cross-Origin Isolation Headers ──────────────────────────────────────
  // Required for SharedArrayBuffer usage (high-resolution timers, etc.)
  response.headers.set('Cross-Origin-Embedder-Policy', 'require-corp');
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin');

  // ── Content-Security-Policy: frame ancestors (clickjacking) ─────────────
  // Allow sub2api to embed this page in an iframe.
  const sub2apiOrigin = extractOrigin(process.env.SUB2API_BASE_URL ?? '');
  const extraOrigins = parseOrigins(process.env.IFRAME_ALLOW_ORIGINS || '');
  const allowedFrameAncestors = buildFrameAncestors(sub2apiOrigin, extraOrigins);

  if (allowedFrameAncestors) {
    response.headers.set(
      'Content-Security-Policy',
      `frame-ancestors 'self' ${allowedFrameAncestors}`
    );
    // Suppress redundant X-Frame-Options when CSP frame-ancestors is used
    response.headers.delete('X-Frame-Options');
  }

  return response;
}

// extractOrigin safely extracts the origin from a full URL.
function extractOrigin(url: string): string {
  if (!url) return '';
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}

// parseOrigins converts a comma-separated list of origins into a clean Set.
// Each entry is validated and the origin is extracted.
function parseOrigins(list: string): Set<string> {
  const origins = new Set<string>();
  for (const s of list.split(',')) {
    const trimmed = s.trim();
    if (!trimmed) continue;
    const origin = extractOrigin(trimmed) || trimmed;
    origins.add(origin);
  }
  return origins;
}

// buildFrameAncestors constructs the frame-ancestors directive value.
// Returns '' if no origins are allowed.
function buildFrameAncestors(
  sub2apiOrigin: string,
  extraOrigins: Set<string>,
): string {
  const allOrigins = new Set<string>();
  if (sub2apiOrigin) allOrigins.add(sub2apiOrigin);
  for (const o of extraOrigins) allOrigins.add(o);
  if (allOrigins.size === 0) return '';
  return [...allOrigins].join(' ');
}

export const config = {
  // Match all routes except Next.js internals
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
