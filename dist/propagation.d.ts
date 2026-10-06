/**
 * DNS propagation probe: query the same record through several resolvers in
 * parallel and report where the answers agree and where they differ. Answers
 * from each resolver are grouped by a canonical fingerprint, so "4 of 6 agree"
 * is counted from the actual record data — never assumed.
 *
 * @module dsh-netdoctor/propagation
 */
import { type DnsAnswer, type DnsRecordType, type DnsResult } from './dns.ts';
/** One resolver to probe. */
export interface PropagationResolver {
    label: string;
    server: string;
}
/**
 * Public resolvers used when the caller does not name its own. Kept as a fixed
 * list (not discovered) so a propagation check is reproducible.
 */
export declare const DEFAULT_RESOLVERS: readonly PropagationResolver[];
/** One resolver's outcome. */
export type PropagationProbe = {
    label: string;
    server: string;
    status: 'ok' | 'error';
    answers: DnsAnswer[];
    elapsedMs: number;
    error?: string;
    timedOut?: boolean;
};
/** All resolvers that returned the same answer set, grouped together. */
export type PropagationGroup = {
    fingerprint: string;
    resolvers: string[];
    answers: DnsAnswer[];
};
/** Result of a propagation check. */
export type PropagationResult = {
    host: string;
    record: DnsRecordType;
    resolvers: number;
    responded: number;
    failed: number;
    /** Every resolver that answered returned the same records. */
    consistent: boolean;
    /** The answer set reported by the most resolvers (omitted when no set has ≥2 reporters). */
    consensus?: {
        fingerprint: string;
        resolvers: string[];
    };
    /** One entry per distinct answer set, most-reported first. */
    groups: PropagationGroup[];
    probes: PropagationProbe[];
    note?: string;
};
/** Lookup function (injectable for tests); same shape as `dnsLookup`. */
export type PropagationLookup = (host: string, record: DnsRecordType, server: string | undefined) => Promise<DnsResult>;
export interface PropagationOptions {
    /** Custom resolver IPs to probe instead of the built-in public set (at most 10). */
    resolvers?: string[];
    /** Per-resolver answer deadline in ms (100–60000, default 5000). */
    timeoutMs?: number;
    /** Lookup implementation override (tests). */
    lookup?: PropagationLookup;
}
/**
 * Canonical fingerprint of an answer set: record type + record data, one line
 * per record, sorted. Order of the answers (and the key order inside each
 * record) therefore cannot change the fingerprint — resolver answer order is
 * not meaningful, and an unstable fingerprint would report false disagreement.
 */
export declare function answerFingerprint(answers: DnsAnswer[]): string;
/**
 * Query one record type through several resolvers and report agreement.
 *
 * A failed or slow resolver is reported as failed — never folded into the
 * majority. `consistent` therefore means "every resolver that answered agreed",
 * and `note` says out loud when the evidence is partial.
 */
export declare function dnsPropagation(hostInput: string, record: DnsRecordType, options?: PropagationOptions): Promise<PropagationResult>;
//# sourceMappingURL=propagation.d.ts.map