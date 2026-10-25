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
export type HttpMethod = 'GET' | 'HEAD';
/** Cumulative marks in ms from the moment the request was issued. */
export type HttpTiming = {
    dnsMs?: number;
    connectMs?: number;
    tlsMs?: number;
    ttfbMs?: number;
    totalMs: number;
};
/** One followed redirect: the URL that answered, its status and where it pointed. */
export type HttpRedirectHop = {
    url: string;
    status: number;
    statusText: string;
    location: string;
};
export type HttpResult = {
    url: string;
    finalUrl: string;
    method: HttpMethod;
    reachable: boolean;
    status: number;
    statusText: string;
    httpVersion?: string;
    redirected: number;
    redirectChain: HttpRedirectHop[];
    headers: Record<string, string>;
    headersTruncated: number;
    setCookieCount: number;
    bodyBytes: number;
    bodyTruncated: boolean;
    timing: HttpTiming;
    note?: string;
    error?: string;
};
export type HttpOptions = {
    method?: HttpMethod;
    maxRedirects?: number;
    bodyLimitBytes?: number;
    timeoutMs?: number;
    insecure?: boolean;
};
/** Default redirect budget. */
export declare const DEFAULT_MAX_REDIRECTS = 5;
/** Default body read budget (bytes). */
export declare const DEFAULT_BODY_LIMIT_BYTES = 8192;
/** Long values (CSP, alt-svc) are cut here so one header cannot flood a context. */
export declare const HEADER_VALUE_CAP = 200;
/** Parse and validate the target URL: absolute, http(s) only, no embedded credentials. */
export declare function parseHttpUrl(input: string): URL;
/** Probe an HTTP(S) endpoint: follow redirects, time each phase, report status and selected headers. */
export declare function checkHttp(input: string, options?: HttpOptions): Promise<HttpResult>;
//# sourceMappingURL=http.d.ts.map