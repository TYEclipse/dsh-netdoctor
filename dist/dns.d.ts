/**
 * DNS record lookup via node:dns — no external services, supports querying an
 * alternative nameserver (handy for testing DNS propagation).
 *
 * @module dsh-netdoctor/dns
 */
import type { JsonValue } from '@deepseek-ai/dsh-tools';
export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'SRV' | 'PTR' | 'CAA';
export type DnsAnswer = {
    name: string;
    type: string;
    ttl: number;
    data: Record<string, JsonValue>;
};
export type DnsResult = {
    host: string;
    record: DnsRecordType;
    server: string;
    answers: DnsAnswer[];
};
/** Render one answer for the text view. */
export declare function renderAnswer(answer: DnsAnswer): string;
/**
 * Resolve DNS records for a host. `server` optionally targets a specific
 * nameserver (IPv4/IPv6); otherwise the system resolver is used.
 */
export declare function dnsLookup(hostInput: string, record: DnsRecordType, server: string | undefined): Promise<DnsResult>;
//# sourceMappingURL=dns.d.ts.map