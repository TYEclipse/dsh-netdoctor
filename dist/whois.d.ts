/**
 * WHOIS lookup over the classic TCP port 43 protocol — no external services
 * beyond the registry servers themselves, zero runtime dependencies
 * (node:net raw socket only).
 *
 * Server discovery follows the standard IANA referral chain: query
 * whois.iana.org first, read the `refer:` line it returns, then re-query the
 * referred registry server. An explicit server can be supplied to skip
 * discovery. The raw WHOIS text is returned alongside a best-effort
 * structured summary (registrar, statuses, dates, nameservers).
 *
 * @module dsh-netdoctor/whois
 */
/** Default WHOIS discovery endpoint (IANA). */
export declare const IANA_SERVER = "whois.iana.org";
/** Cap on the raw WHOIS text returned to the caller (context budget). */
export declare const RAW_CAP = 12000;
/** Extract the last label (TLD) of a hostname, lowercased. */
export declare function tldOf(host: string): string;
/**
 * Fallback WHOIS server for a host: ARIN for IP literals (the conventional
 * default RIR; non-ARIN ranges answer with a ReferralServer line in the raw
 * text), otherwise the TLD map.
 */
export declare function fallbackWhoisServer(host: string): string | undefined;
/** Best-effort structured summary of a WHOIS response. */
export interface WhoisSummary {
    registrar?: string;
    statuses: string[];
    createdDate?: string;
    updatedDate?: string;
    expiryDate?: string;
    nameServers: string[];
}
/** Full result of a WHOIS lookup. */
export interface WhoisResult {
    domain: string;
    /** Registry server that produced the answer. */
    server: string;
    /** Raw WHOIS text (capped at {@link RAW_CAP}). */
    raw: string;
    rawTruncated: boolean;
    summary: WhoisSummary;
    /** Set when the lookup failed; raw/summary are then empty. */
    error?: string;
}
/**
 * Open a raw TCP connection to a WHOIS server on port 43 (configurable for
 * tests), send the query line, and collect the full response.
 * Resolves with the response text; rejects with a descriptive error on
 * connection failure or timeout before any data arrives.
 */
export declare function rawWhoisQuery(server: string, query: string, timeoutMs: number, port?: number): Promise<string>;
/** Extract the `refer:` server from an IANA WHOIS response, if present. */
export declare function parseIanaReferral(text: string): string | undefined;
/** Best-effort extraction of the structured fields agents care about. */
export declare function parseWhoisSummary(text: string): WhoisSummary;
/**
 * Perform a WHOIS lookup for a domain or IP address. With an explicit
 * `server` the query goes straight there; otherwise whois.iana.org is
 * consulted first and its `refer:` line is followed to the registry server.
 * If discovery is unreachable or returns no referral, a best-effort fallback
 * server is tried (TLD map, ARIN for IP literals). Failures are reported in
 * `error` rather than thrown, so the tool always returns a structured result.
 */
export declare function whoisLookup(domainInput: string, server: string | undefined, timeoutMs: number): Promise<WhoisResult>;
//# sourceMappingURL=whois.d.ts.map