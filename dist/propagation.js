/**
 * DNS propagation probe: query the same record through several resolvers in
 * parallel and report where the answers agree and where they differ. Answers
 * from each resolver are grouped by a canonical fingerprint, so "4 of 6 agree"
 * is counted from the actual record data — never assumed.
 *
 * @module dsh-netdoctor/propagation
 */
import { dnsLookup } from "./dns.js";
import { assertValidResolver, assertValidTarget, round2 } from "./util.js";
/**
 * Public resolvers used when the caller does not name its own. Kept as a fixed
 * list (not discovered) so a propagation check is reproducible.
 */
export const DEFAULT_RESOLVERS = [
    { label: 'Google', server: '8.8.8.8' },
    { label: 'Cloudflare', server: '1.1.1.1' },
    { label: 'Quad9', server: '9.9.9.9' },
    { label: 'OpenDNS', server: '208.67.222.222' },
    { label: 'Level3', server: '4.2.2.1' },
    { label: 'DNS.SB', server: '185.222.222.222' },
];
/** Deterministic serialization of a JSON value with sorted object keys. */
function stableValue(value) {
    if (Array.isArray(value))
        return `[${value.map(stableValue).join(',')}]`;
    if (value !== null && typeof value === 'object') {
        const entries = Object.keys(value)
            .sort()
            .map((key) => `${key}=${stableValue(value[key] ?? null)}`);
        return `{${entries.join(',')}}`;
    }
    return JSON.stringify(value) ?? 'null';
}
/**
 * Canonical fingerprint of an answer set: record type + record data, one line
 * per record, sorted. Order of the answers (and the key order inside each
 * record) therefore cannot change the fingerprint — resolver answer order is
 * not meaningful, and an unstable fingerprint would report false disagreement.
 */
export function answerFingerprint(answers) {
    return answers
        .map((answer) => `${answer.type} ${stableValue(answer.data)}`)
        .sort()
        .join('\n');
}
async function probeOnce(resolver, host, record, timeoutMs, lookup) {
    const startedAt = Date.now();
    let timedOut = false;
    let timer;
    const deadline = new Promise((_resolve, reject) => {
        timer = setTimeout(() => {
            timedOut = true;
            reject(new Error(`no answer from ${resolver.server} within ${timeoutMs} ms`));
        }, timeoutMs);
    });
    try {
        const result = await Promise.race([lookup(host, record, resolver.server), deadline]);
        return {
            label: resolver.label,
            server: resolver.server,
            status: 'ok',
            answers: result.answers,
            elapsedMs: round2(Date.now() - startedAt),
        };
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return timedOut
            ? {
                label: resolver.label,
                server: resolver.server,
                status: 'error',
                answers: [],
                elapsedMs: round2(Date.now() - startedAt),
                error: message,
                timedOut: true,
            }
            : {
                label: resolver.label,
                server: resolver.server,
                status: 'error',
                answers: [],
                elapsedMs: round2(Date.now() - startedAt),
                error: message,
            };
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}
/**
 * Query one record type through several resolvers and report agreement.
 *
 * A failed or slow resolver is reported as failed — never folded into the
 * majority. `consistent` therefore means "every resolver that answered agreed",
 * and `note` says out loud when the evidence is partial.
 */
export async function dnsPropagation(hostInput, record, options = {}) {
    const host = assertValidTarget(hostInput);
    const timeoutMs = options.timeoutMs ?? 5_000;
    if (typeof timeoutMs !== 'number' || timeoutMs < 100 || timeoutMs > 60_000) {
        throw new Error('timeoutMs must be a number between 100 and 60000');
    }
    const custom = options.resolvers;
    let resolvers;
    if (custom !== undefined && custom.length > 0) {
        if (custom.length > 10) {
            throw new Error(`at most 10 resolvers per propagation check (got ${custom.length})`);
        }
        resolvers = custom.map((server) => {
            const valid = assertValidResolver(server);
            return { label: valid, server: valid };
        });
    }
    else {
        resolvers = [...DEFAULT_RESOLVERS];
    }
    const lookup = options.lookup ?? dnsLookup;
    const probes = await Promise.all(resolvers.map((resolver) => probeOnce(resolver, host, record, timeoutMs, lookup)));
    const answered = probes.filter((probe) => probe.status === 'ok');
    const groups = [];
    for (const probe of answered) {
        const fingerprint = answerFingerprint(probe.answers);
        let group = groups.find((candidate) => candidate.fingerprint === fingerprint);
        if (group === undefined) {
            group = { fingerprint, resolvers: [], answers: probe.answers };
            groups.push(group);
        }
        group.resolvers.push(probe.label);
    }
    // Most-reported answer set first; equal sizes keep resolver order (stable sort).
    groups.sort((a, b) => b.resolvers.length - a.resolvers.length);
    const failed = probes.length - answered.length;
    const notes = [];
    if (answered.length === 0) {
        notes.push(`no resolver answered (${probes.length} probed)`);
    }
    else if (failed > 0) {
        notes.push(`${failed} of ${probes.length} resolvers did not answer — agreement is partial`);
    }
    if (groups.length > 1) {
        notes.push(`resolvers disagree: ${groups.length} distinct answer sets`);
    }
    const top = groups[0];
    const result = {
        host,
        record,
        resolvers: probes.length,
        responded: answered.length,
        failed,
        consistent: answered.length > 0 && groups.length === 1,
        groups,
        probes,
    };
    if (top !== undefined && top.resolvers.length >= 2) {
        result.consensus = { fingerprint: top.fingerprint, resolvers: top.resolvers };
    }
    if (notes.length > 0)
        result.note = notes.join('; ');
    return result;
}
//# sourceMappingURL=propagation.js.map