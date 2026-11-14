/**
 * Mail-delivery DNS readiness: does this domain actually accept mail, and are
 * the three policies that decide whether receivers trust it (SPF, DMARC,
 * DKIM) present and sane? Every answer is derived from DNS records only —
 * nothing is guessed, and a record that is missing is reported as missing
 * rather than as a zero.
 *
 * @module dsh-netdoctor/email
 */
import { type DnsRecordType, type DnsResult } from './dns.ts';
/** Lookup function shape, injectable so tests never touch the network. */
export type EmailLookup = (host: string, record: DnsRecordType) => Promise<DnsResult>;
export type EmailSeverity = 'error' | 'warning' | 'info';
/** One machine-readable finding: a stable `code` plus a human sentence. */
export type EmailFinding = {
    severity: EmailSeverity;
    code: string;
    message: string;
};
/** Parsed SPF record (RFC 7208). */
export type SpfReport = {
    found: boolean;
    records: string[];
    selected?: string;
    multiple: boolean;
    terms: string[];
    dnsLookups: number;
    lookupLimit: number;
    exceedsLimit: boolean;
    allQualifier?: string;
    allIsLast: boolean;
    includes: string[];
    redirect?: string;
    unknownTerms: string[];
    error?: string;
};
/** Parsed DMARC record (RFC 7489). */
export type DmarcReport = {
    found: boolean;
    name: string;
    records: string[];
    selected?: string;
    usable: boolean;
    versionFirst: boolean;
    tags: Record<string, string>;
    policy?: string;
    subdomainPolicy?: string;
    percentage?: number;
    reportingUris: string[];
    forensicUris: string[];
    duplicateTags: string[];
    error?: string;
};
/** One DKIM selector probe (RFC 6376). */
export type DkimReport = {
    selector: string;
    name: string;
    found: boolean;
    revoked: boolean;
    keyType?: string;
    error?: string;
};
/** Full email readiness report. */
export type EmailDnsResult = {
    domain: string;
    mailAccepted: boolean;
    mx: Array<{
        exchange: string;
        priority: number;
    }>;
    nullMx: boolean;
    implicitMx: boolean;
    fallbackAddresses: string[];
    mxError?: string;
    spf: SpfReport;
    dmarc: DmarcReport;
    dkim: DkimReport[];
    findings: EmailFinding[];
    note?: string;
};
/** RFC 7208 §4.6.4: at most 10 DNS-querying terms across the whole evaluation. */
export declare const SPF_LOOKUP_LIMIT = 10;
/** Default DMARC percentage when the tag is absent (RFC 7489 §6.3, pct default 100). */
export declare const DMARC_DEFAULT_PCT = 100;
/** Maximum number of DKIM selectors one call may probe. */
export declare const MAX_DKIM_SELECTORS = 5;
/** Join the character-strings of one TXT record (RFC 7208 §3.3: no separator). */
export declare function assembleTxt(entries: string[]): string;
/** True when a TXT record opens with the SPF version tag. */
export declare function isSpfRecord(raw: string): boolean;
/** True when a TXT record opens with the DMARC version tag. */
export declare function isDmarcRecord(raw: string): boolean;
/** Classify one SPF term: does it cause a DNS query, and is it well formed? */
export declare function classifySpfTerm(rawTerm: string): {
    dns: boolean;
    kind: string;
    unknown: boolean;
};
/**
 * Parse one SPF record. Returns `undefined` when the string is not an SPF
 * record at all — "not SPF" must not look like "SPF with zero lookups".
 */
export declare function parseSpfRecord(raw: string): {
    terms: string[];
    dnsLookups: number;
    allQualifier?: string;
    allIsLast: boolean;
    includes: string[];
    redirect?: string;
    unknownTerms: string[];
} | undefined;
/** Parse one DMARC record into ordered tags (first occurrence wins). */
export declare function parseDmarcRecord(raw: string): {
    tags: Record<string, string>;
    tagOrder: string[];
    versionFirst: boolean;
    duplicateTags: string[];
};
/** Parse a DKIM key record into tag/value pairs. */
export declare function parseDkimRecord(raw: string): Record<string, string>;
/**
 * Check a domain's mail-delivery DNS: MX records (including the null-MX "no
 * mail here" signal), SPF, DMARC, and optionally one or more DKIM selectors.
 * Read-only; a failed lookup is reported as a failure, never as "no records".
 */
export declare function emailDns(domainInput: string, options?: {
    dkimSelectors?: string[];
    lookup?: EmailLookup;
}): Promise<EmailDnsResult>;
//# sourceMappingURL=email.d.ts.map