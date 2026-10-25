/**
 * HTTP endpoint probe: one request (following redirects) with a per-phase
 * timing breakdown, the status line, selected response headers and a bounded
 * body read.
 *
 * The question this probe answers is "which layer is slow, and where did the
 * redirect go" — so every number is measured on the socket instead of guessed.
 * `dnsMs`, `connectMs`, `tlsMs`, `ttfbMs` and `totalMs` are cumulative marks
 * taken from the same monotonic clock, which makes
 * `dns ≤ connect ≤ tls ≤ ttfb ≤ total` a checkable invariant rather than a
 * convention.
 *
 * @module dsh-netdoctor/http
 */
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { round2 } from "./util.js";
/** Default redirect budget. */
export const DEFAULT_MAX_REDIRECTS = 5;
/** Default body read budget (bytes). */
export const DEFAULT_BODY_LIMIT_BYTES = 8_192;
/** Long values (CSP, alt-svc) are cut here so one header cannot flood a context. */
export const HEADER_VALUE_CAP = 200;
/**
 * Headers worth reporting: response identity, caching, and the security
 * headers a person actually audits. Everything else is left out on purpose —
 * the tool answers questions, it does not dump the wire.
 */
const INTERESTING_HEADERS = [
    'content-type',
    'content-length',
    'content-encoding',
    'server',
    'date',
    'age',
    'via',
    'location',
    'cache-control',
    'etag',
    'last-modified',
    'vary',
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'access-control-allow-origin',
    'alt-svc',
];
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
/** Parse and validate the target URL: absolute, http(s) only, no embedded credentials. */
export function parseHttpUrl(input) {
    const text = input.trim();
    if (text === '')
        throw new Error('url must not be empty');
    let url;
    try {
        url = new URL(text);
    }
    catch {
        throw new Error(`url "${input}" is not a valid absolute URL (include the scheme, e.g. https://example.com/)`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error(`url scheme must be http or https (got "${url.protocol.replace(':', '')}")`);
    }
    if (url.hostname === '')
        throw new Error(`url "${input}" has no host`);
    if (url.username !== '' || url.password !== '') {
        throw new Error('url must not embed credentials — this probe is read-only diagnostics and never authenticates');
    }
    return url;
}
function assertTimeoutMs(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 100 || value > 60_000) {
        throw new Error('timeoutMs must be a number between 100 and 60000');
    }
    return value;
}
function assertMaxRedirects(value) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 10) {
        throw new Error(`maxRedirects must be an integer between 0 and 10 (got ${String(value)})`);
    }
    return value;
}
function assertBodyLimit(value) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 1_000_000) {
        throw new Error(`bodyLimitBytes must be an integer between 1 and 1000000 (got ${String(value)})`);
    }
    return value;
}
function selectHeaders(response) {
    const headers = {};
    let truncated = 0;
    for (const name of INTERESTING_HEADERS) {
        const raw = response.headers[name];
        if (raw === undefined)
            continue;
        const value = Array.isArray(raw) ? raw.join(', ') : raw;
        if (value.length > HEADER_VALUE_CAP) {
            headers[name] = value.slice(0, HEADER_VALUE_CAP);
            truncated += 1;
        }
        else {
            headers[name] = value;
        }
    }
    const cookies = response.headers['set-cookie'];
    const setCookieCount = cookies === undefined ? 0 : Array.isArray(cookies) ? cookies.length : 1;
    return { headers, truncated, setCookieCount };
}
/** Run a single request (no redirect following) and measure every phase it passes through. */
function performHop(url, method, timeoutMs, bodyLimitBytes, insecure) {
    return new Promise((resolve) => {
        const started = performance.now();
        const elapsed = () => round2(performance.now() - started);
        let dnsMs;
        let connectMs;
        let tlsMs;
        let settled = false;
        let timer;
        const finish = (outcome) => {
            if (settled)
                return;
            settled = true;
            if (timer !== undefined)
                clearTimeout(timer);
            const timing = { totalMs: outcome.totalMs };
            if (dnsMs !== undefined)
                timing.dnsMs = dnsMs;
            if (connectMs !== undefined)
                timing.connectMs = connectMs;
            if (tlsMs !== undefined)
                timing.tlsMs = tlsMs;
            if (outcome.status > 0)
                timing.ttfbMs = outcome.ttfbMs ?? outcome.totalMs;
            resolve({
                status: outcome.status,
                statusText: outcome.statusText,
                httpVersion: outcome.httpVersion,
                location: outcome.location,
                headers: outcome.headers,
                headersTruncated: outcome.headersTruncated,
                setCookieCount: outcome.setCookieCount,
                bodyBytes: outcome.bodyBytes,
                bodyTruncated: outcome.bodyTruncated,
                timing,
                error: outcome.error,
            });
        };
        const fail = (detail) => {
            finish({
                status: 0,
                statusText: '',
                httpVersion: undefined,
                location: undefined,
                headers: {},
                headersTruncated: 0,
                setCookieCount: 0,
                bodyBytes: 0,
                bodyTruncated: false,
                error: detail,
                totalMs: elapsed(),
            });
        };
        const options = {
            method,
            headers: { 'user-agent': 'dsh-netdoctor/0.4', accept: '*/*' },
            agent: false,
            ...(insecure ? { rejectUnauthorized: false } : {}),
        };
        let request;
        try {
            request = url.protocol === 'https:' ? httpsRequest(url, options) : httpRequest(url, options);
        }
        catch (error) {
            fail(error instanceof Error ? error.message : String(error));
            return;
        }
        request.on('socket', (socket) => {
            socket.once('lookup', () => {
                dnsMs = elapsed();
            });
            socket.once('connect', () => {
                connectMs = elapsed();
            });
            socket.once('secureConnect', () => {
                tlsMs = elapsed();
            });
        });
        timer = setTimeout(() => {
            request.destroy(new Error(`request did not complete within ${timeoutMs} ms`));
        }, timeoutMs);
        request.on('response', (response) => {
            const ttfbMs = elapsed();
            const { headers, truncated, setCookieCount } = selectHeaders(response);
            const status = response.statusCode ?? 0;
            const location = typeof response.headers.location === 'string' ? response.headers.location : undefined;
            const base = {
                status,
                statusText: response.statusMessage ?? '',
                httpVersion: response.httpVersion,
                location,
                headers,
                headersTruncated: truncated,
                setCookieCount,
            };
            let bodyBytes = 0;
            let bodyTruncated = false;
            // A HEAD response carries no body; destroying it immediately is correct
            // and keeps the totals from waiting on a connection the server will idle.
            if (method === 'HEAD') {
                response.destroy();
                finish({ ...base, bodyBytes: 0, bodyTruncated: false, error: undefined, ttfbMs, totalMs: ttfbMs });
                return;
            }
            response.on('data', (chunk) => {
                bodyBytes += chunk.length;
                if (bodyBytes > bodyLimitBytes) {
                    bodyTruncated = true;
                    response.destroy();
                    finish({ ...base, bodyBytes, bodyTruncated, error: undefined, ttfbMs, totalMs: elapsed() });
                }
            });
            response.on('end', () => {
                finish({ ...base, bodyBytes, bodyTruncated: false, error: undefined, ttfbMs, totalMs: elapsed() });
            });
            // Destroying a response mid-body surfaces as an error event; the outcome
            // is already recorded, so swallow it rather than crashing the probe.
            response.on('error', () => { });
        });
        request.on('error', (error) => {
            const code = error.code ?? '';
            if (code === 'ECONNREFUSED')
                fail(`connection refused on port ${url.port === '' ? (url.protocol === 'https:' ? '443' : '80') : url.port}`);
            else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN')
                fail(`host lookup failed: ${error.message}`);
            else if (code === 'ECONNRESET')
                fail('connection reset by the peer before the response completed');
            else if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALT_NAME/i.test(String(error.code ?? '') + error.message)) {
                fail(`certificate rejected: ${error.message} (use insecure: true only to inspect a known-bad endpoint)`);
            }
            else
                fail(error.message);
        });
        request.end();
    });
}
/** Probe an HTTP(S) endpoint: follow redirects, time each phase, report status and selected headers. */
export async function checkHttp(input, options = {}) {
    const first = parseHttpUrl(input);
    const method = options.method ?? 'GET';
    if (method !== 'GET' && method !== 'HEAD') {
        throw new Error(`method must be "GET" or "HEAD" (got ${String(options.method)})`);
    }
    const timeoutMs = assertTimeoutMs(options.timeoutMs ?? 5_000);
    const maxRedirects = assertMaxRedirects(options.maxRedirects ?? DEFAULT_MAX_REDIRECTS);
    const bodyLimitBytes = assertBodyLimit(options.bodyLimitBytes ?? DEFAULT_BODY_LIMIT_BYTES);
    const insecure = options.insecure ?? false;
    if (typeof insecure !== 'boolean')
        throw new Error('insecure must be a boolean');
    const redirectChain = [];
    let current = first;
    let outcome;
    let note;
    let stoppedByLimit = false;
    let schemeDowngrade = false;
    for (;;) {
        outcome = await performHop(current, method, timeoutMs, bodyLimitBytes, insecure);
        if (outcome.error !== undefined)
            break;
        const location = outcome.location;
        if (!REDIRECT_STATUSES.has(outcome.status) || location === undefined)
            break;
        if (redirectChain.length >= maxRedirects) {
            stoppedByLimit = true;
            break;
        }
        let next;
        try {
            next = new URL(location, current);
        }
        catch {
            note = `the redirect target "${location}" is not a resolvable URL`;
            break;
        }
        redirectChain.push({
            url: current.toString(),
            status: outcome.status,
            statusText: outcome.statusText,
            location: next.toString(),
        });
        if (current.protocol === 'https:' && next.protocol === 'http:')
            schemeDowngrade = true;
        current = next;
    }
    if (outcome === undefined)
        throw new Error('internal error: no probe outcome'); // unreachable, keeps the type narrow
    const finalUrl = current.toString();
    const notes = [];
    if (note !== undefined)
        notes.push(note);
    if (stoppedByLimit)
        notes.push(`stopped after ${maxRedirects} redirect(s) — the maxRedirects limit was reached`);
    if (schemeDowngrade)
        notes.push('a redirect moved this request from https to http, so the rest travels in clear text');
    if (outcome.error === undefined && outcome.status === 0)
        notes.push('the server answered without a status line');
    const result = {
        url: input.trim(),
        finalUrl,
        method,
        reachable: outcome.error === undefined && outcome.status > 0,
        status: outcome.status,
        statusText: outcome.statusText,
        httpVersion: outcome.httpVersion,
        redirected: redirectChain.length,
        redirectChain,
        headers: outcome.headers,
        headersTruncated: outcome.headersTruncated,
        setCookieCount: outcome.setCookieCount,
        bodyBytes: outcome.bodyBytes,
        bodyTruncated: outcome.bodyTruncated,
        timing: outcome.timing,
    };
    if (notes.length > 0)
        result.note = notes.join('; ');
    if (outcome.error !== undefined)
        result.error = outcome.error;
    return result;
}
//# sourceMappingURL=http.js.map