/**
 * Mail-delivery DNS readiness: does this domain actually accept mail, and are
 * the three policies that decide whether receivers trust it (SPF, DMARC,
 * DKIM) present and sane? Every answer is derived from DNS records only —
 * nothing is guessed, and a record that is missing is reported as missing
 * rather than as a zero.
 *
 * @module dsh-netdoctor/email
 */
import { dnsLookup } from "./dns.js";
import { assertValidTarget } from "./util.js";
/** RFC 7208 §4.6.4: at most 10 DNS-querying terms across the whole evaluation. */
export const SPF_LOOKUP_LIMIT = 10;
/** Default DMARC percentage when the tag is absent (RFC 7489 §6.3, pct default 100). */
export const DMARC_DEFAULT_PCT = 100;
/** Maximum number of DKIM selectors one call may probe. */
export const MAX_DKIM_SELECTORS = 5;
const SELECTOR_RE = /^[A-Za-z0-9._-]{1,63}$/;
const QUALIFIER_RE = /^[+\-~?]/;
const DNS_TERM_RE = /^(?:include|exists|a|mx|ptr)(?::|\/|$)/;
const IP_TERM_RE = /^ip[46]:/;
const MODIFIER_RE = /^([A-Za-z][A-Za-z0-9_.-]*)=(.+)$/;
/** Join the character-strings of one TXT record (RFC 7208 §3.3: no separator). */
export function assembleTxt(entries) {
    return entries.join('');
}
/** True when a TXT record opens with the SPF version tag. */
export function isSpfRecord(raw) {
    return /^v=spf1(?:\s|$)/i.test(raw.trim());
}
/** True when a TXT record opens with the DMARC version tag. */
export function isDmarcRecord(raw) {
    return /^v=DMARC1(?:\s*;|$)/i.test(raw.trim());
}
/** Classify one SPF term: does it cause a DNS query, and is it well formed? */
export function classifySpfTerm(rawTerm) {
    const qualified = rawTerm.replace(QUALIFIER_RE, '');
    const term = qualified.trim();
    if (term === '' || term === 'all')
        return { dns: false, kind: 'all', unknown: false };
    if (IP_TERM_RE.test(term))
        return { dns: false, kind: 'ip', unknown: false };
    const modifier = MODIFIER_RE.exec(term);
    if (modifier !== null) {
        const key = (modifier[1] ?? '').toLowerCase();
        if (key === 'redirect')
            return { dns: true, kind: 'redirect', unknown: false };
        if (key === 'exp')
            return { dns: false, kind: 'exp', unknown: false };
        return { dns: false, kind: 'modifier', unknown: false };
    }
    if (DNS_TERM_RE.test(term)) {
        const kind = term.split(/[:/]/, 1)[0] ?? '';
        return { dns: true, kind, unknown: false };
    }
    return { dns: false, kind: 'unknown', unknown: true };
}
/**
 * Parse one SPF record. Returns `undefined` when the string is not an SPF
 * record at all — "not SPF" must not look like "SPF with zero lookups".
 */
export function parseSpfRecord(raw) {
    const text = raw.trim();
    if (!isSpfRecord(text))
        return undefined;
    const terms = text.split(/\s+/).slice(1).filter((term) => term !== '');
    let dnsLookups = 0;
    const includes = [];
    const unknownTerms = [];
    let redirect;
    let allIndex = -1;
    let allQualifier;
    terms.forEach((term, index) => {
        const verdict = classifySpfTerm(term);
        if (verdict.dns)
            dnsLookups += 1;
        if (verdict.unknown)
            unknownTerms.push(term);
        const bare = term.replace(QUALIFIER_RE, '');
        if (bare === 'all') {
            if (allIndex === -1) {
                allIndex = index;
                allQualifier = QUALIFIER_RE.exec(term)?.[0] ?? '+';
            }
            return;
        }
        if (bare.toLowerCase().startsWith('include:'))
            includes.push(bare.slice('include:'.length));
        const modifier = MODIFIER_RE.exec(bare);
        if (modifier !== null && (modifier[1] ?? '').toLowerCase() === 'redirect')
            redirect = modifier[2];
    });
    const parsed = {
        terms,
        dnsLookups,
        allIsLast: allIndex !== -1 && allIndex === terms.length - 1,
        includes,
        unknownTerms,
    };
    if (allQualifier !== undefined)
        parsed.allQualifier = allQualifier;
    if (redirect !== undefined)
        parsed.redirect = redirect;
    return parsed;
}
/** Parse one DMARC record into ordered tags (first occurrence wins). */
export function parseDmarcRecord(raw) {
    const tags = {};
    const tagOrder = [];
    const duplicateTags = [];
    for (const segment of raw.split(';')) {
        const part = segment.trim();
        if (part === '')
            continue;
        const eq = part.indexOf('=');
        if (eq <= 0)
            continue;
        const key = part.slice(0, eq).trim().toLowerCase();
        const value = part.slice(eq + 1).trim();
        if (key === '')
            continue;
        if (Object.hasOwn(tags, key)) {
            duplicateTags.push(key);
            continue;
        }
        tags[key] = value;
        tagOrder.push(key);
    }
    return {
        tags,
        tagOrder,
        versionFirst: tagOrder[0] === 'v' && (tags.v ?? '').toLowerCase() === 'dmarc1',
        duplicateTags,
    };
}
/** Parse a DKIM key record into tag/value pairs. */
export function parseDkimRecord(raw) {
    const tags = {};
    for (const segment of raw.split(';')) {
        const part = segment.trim();
        if (part === '')
            continue;
        const eq = part.indexOf('=');
        if (eq <= 0)
            continue;
        tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
    }
    return tags;
}
function txtRecords(result) {
    return result.answers
        .filter((answer) => answer.type === 'TXT')
        .map((answer) => assembleTxt(Array.isArray(answer.data.entries) ? answer.data.entries.map(String) : [String(answer.data.entries)]));
}
function mxRecords(result) {
    return result.answers
        .filter((answer) => answer.type === 'MX')
        .map((answer) => ({
        exchange: String(answer.data.exchange ?? ''),
        priority: Number(answer.data.priority ?? 0),
    }));
}
function addresses(result) {
    return result.answers
        .filter((answer) => answer.type === 'A' || answer.type === 'AAAA')
        .map((answer) => String(answer.data.address ?? ''));
}
function errorText(error) {
    return error instanceof Error ? error.message : String(error);
}
/**
 * A name with no record of that type is *absent*, not *failed*: node's resolver
 * throws ENODATA (name exists, no such record) or ENOTFOUND (name does not
 * exist) for both cases. Reporting those as errors would turn "no DMARC record
 * published" into a network incident; reporting a real timeout as "absent"
 * would hide one.
 */
function isMissingRecordError(error) {
    const message = errorText(error).toUpperCase();
    return message.includes('ENODATA') || message.includes('ENOTFOUND') || message.includes('NOTFOUND');
}
function severityRank(severity) {
    if (severity === 'error')
        return 0;
    if (severity === 'warning')
        return 1;
    return 2;
}
function emptySpf(error) {
    const report = {
        found: false,
        records: [],
        multiple: false,
        terms: [],
        dnsLookups: 0,
        lookupLimit: SPF_LOOKUP_LIMIT,
        exceedsLimit: false,
        allIsLast: false,
        includes: [],
        unknownTerms: [],
    };
    if (error !== undefined)
        report.error = error;
    return report;
}
function emptyDmarc(domain, error) {
    const report = {
        found: false,
        name: `_dmarc.${domain}`,
        records: [],
        usable: false,
        versionFirst: false,
        tags: {},
        reportingUris: [],
        forensicUris: [],
        duplicateTags: [],
    };
    if (error !== undefined)
        report.error = error;
    return report;
}
function splitUris(value) {
    if (value === undefined)
        return [];
    return value
        .split(',')
        .map((uri) => uri.trim())
        .filter((uri) => uri !== '');
}
/**
 * Check a domain's mail-delivery DNS: MX records (including the null-MX "no
 * mail here" signal), SPF, DMARC, and optionally one or more DKIM selectors.
 * Read-only; a failed lookup is reported as a failure, never as "no records".
 */
export async function emailDns(domainInput, options = {}) {
    const domain = assertValidTarget(domainInput, 'domain').toLowerCase();
    const lookup = options.lookup ?? ((host, record) => dnsLookup(host, record, undefined));
    const findings = [];
    const selectors = [];
    for (const rawSelector of options.dkimSelectors ?? []) {
        const selector = rawSelector.trim();
        if (!SELECTOR_RE.test(selector)) {
            throw new Error(`DKIM selector "${rawSelector}" is not a valid selector label (letters, digits, dot, dash, underscore; at most 63 characters)`);
        }
        if (!selectors.includes(selector))
            selectors.push(selector);
    }
    if (selectors.length > MAX_DKIM_SELECTORS) {
        throw new Error(`at most ${MAX_DKIM_SELECTORS} DKIM selectors per call (got ${selectors.length})`);
    }
    // ---- MX -----------------------------------------------------------------
    let mx = [];
    let mxError;
    try {
        mx = mxRecords(await lookup(domain, 'MX'));
    }
    catch (error) {
        if (!isMissingRecordError(error))
            mxError = errorText(error);
    }
    mx.sort((left, right) => (left.priority === right.priority
        ? left.exchange.localeCompare(right.exchange)
        : left.priority - right.priority));
    const nullMx = mx.length === 1 && mx[0] !== undefined && mx[0].priority === 0
        && (mx[0].exchange === '.' || mx[0].exchange === '');
    let implicitMx = false;
    let fallbackAddresses = [];
    if (mxError !== undefined) {
        findings.push({ severity: 'error', code: 'mx-error', message: `MX lookup failed: ${mxError}` });
    }
    else if (nullMx) {
        findings.push({
            severity: 'info',
            code: 'mx-null',
            message: 'a null MX ("0 .") is published: this domain deliberately accepts no mail (RFC 7505)',
        });
    }
    else if (mx.length === 0) {
        implicitMx = true;
        let addressError;
        try {
            fallbackAddresses = addresses(await lookup(domain, 'A'));
        }
        catch (error) {
            if (!isMissingRecordError(error))
                addressError = errorText(error);
        }
        if (addressError !== undefined) {
            findings.push({ severity: 'error', code: 'address-error', message: `A/AAAA lookup failed: ${addressError}` });
        }
        else if (fallbackAddresses.length === 0) {
            findings.push({
                severity: 'error',
                code: 'domain-not-found',
                message: 'the domain has neither MX nor A/AAAA records, so it does not resolve and cannot receive mail',
            });
        }
        else {
            findings.push({
                severity: 'warning',
                code: 'mx-missing',
                message: `no MX records; mail falls back to the A/AAAA address(es) ${fallbackAddresses.join(', ')} (RFC 5321 §5.1)`,
            });
        }
    }
    const mailAccepted = !nullMx && (mx.length > 0 || fallbackAddresses.length > 0);
    // ---- SPF ----------------------------------------------------------------
    let spfRecords = [];
    let spfError;
    try {
        spfRecords = txtRecords(await lookup(domain, 'TXT')).filter(isSpfRecord);
    }
    catch (error) {
        if (!isMissingRecordError(error))
            spfError = errorText(error);
    }
    let spf = emptySpf(spfError);
    if (spfRecords.length > 0) {
        const selected = spfRecords[0] ?? '';
        const parsed = parseSpfRecord(selected);
        if (parsed !== undefined) {
            spf = {
                found: true,
                records: spfRecords,
                multiple: spfRecords.length > 1,
                terms: parsed.terms,
                dnsLookups: parsed.dnsLookups,
                lookupLimit: SPF_LOOKUP_LIMIT,
                exceedsLimit: parsed.dnsLookups > SPF_LOOKUP_LIMIT,
                allIsLast: parsed.allIsLast,
                includes: parsed.includes,
                unknownTerms: parsed.unknownTerms,
            };
            if (parsed.allQualifier !== undefined)
                spf.allQualifier = parsed.allQualifier;
            if (parsed.redirect !== undefined)
                spf.redirect = parsed.redirect;
            spf.selected = selected;
        }
    }
    if (spf.found) {
        if (spf.multiple) {
            findings.push({
                severity: 'error',
                code: 'spf-multiple',
                message: `${spf.records.length} SPF records published; per RFC 7208 §3.2 that is a permanent error, so receivers must ignore all of them`,
            });
        }
        if (spf.exceedsLimit) {
            findings.push({
                severity: 'warning',
                code: 'spf-too-many-lookups',
                message: `${spf.dnsLookups} DNS-querying terms in this record alone (limit ${SPF_LOOKUP_LIMIT}); includes are evaluated recursively against the same budget, so the real total is higher`,
            });
        }
        if (spf.allQualifier === undefined) {
            findings.push({
                severity: 'info',
                code: 'spf-no-all',
                message: 'no "all" mechanism: addresses that match nothing get a neutral result, so the record licenses nothing and forbids nothing',
            });
        }
        else {
            if (spf.allQualifier === '+' || spf.allQualifier === '?') {
                findings.push({
                    severity: 'warning',
                    code: 'spf-permissive',
                    message: `"${spf.allQualifier}all" makes every non-matching sender pass or neutral — the record does not protect the domain`,
                });
            }
            if (!spf.allIsLast) {
                findings.push({
                    severity: 'warning',
                    code: 'spf-all-not-last',
                    message: '"all" is not the last mechanism, so terms after it can never be reached',
                });
            }
        }
        if (spf.unknownTerms.length > 0) {
            findings.push({
                severity: 'warning',
                code: 'spf-unknown-term',
                message: `unrecognised SPF terms: ${spf.unknownTerms.join(', ')}`,
            });
        }
    }
    else if (spfError === undefined) {
        findings.push({
            severity: 'warning',
            code: 'spf-missing',
            message: 'no SPF record (a TXT record starting with "v=spf1") — receivers cannot tell your senders from anyone else',
        });
    }
    else {
        findings.push({ severity: 'error', code: 'spf-error', message: `TXT lookup failed: ${spfError}` });
    }
    // ---- DMARC --------------------------------------------------------------
    const dmarcName = `_dmarc.${domain}`;
    let dmarcRecords = [];
    let dmarcError;
    try {
        dmarcRecords = txtRecords(await lookup(dmarcName, 'TXT')).filter(isDmarcRecord);
    }
    catch (error) {
        if (!isMissingRecordError(error))
            dmarcError = errorText(error);
    }
    let dmarc = emptyDmarc(domain, dmarcError);
    if (dmarcRecords.length > 0) {
        const selected = dmarcRecords[0] ?? '';
        const parsed = parseDmarcRecord(selected);
        const policy = parsed.tags.p;
        const pct = parsed.tags.pct === undefined ? undefined : Number(parsed.tags.pct);
        dmarc = {
            found: true,
            name: dmarcName,
            records: dmarcRecords,
            selected,
            usable: parsed.versionFirst && dmarcRecords.length === 1,
            versionFirst: parsed.versionFirst,
            tags: parsed.tags,
            reportingUris: splitUris(parsed.tags.rua),
            forensicUris: splitUris(parsed.tags.ruf),
            duplicateTags: parsed.duplicateTags,
        };
        if (policy !== undefined)
            dmarc.policy = policy;
        if (parsed.tags.sp !== undefined)
            dmarc.subdomainPolicy = parsed.tags.sp;
        if (pct !== undefined && Number.isFinite(pct))
            dmarc.percentage = pct;
    }
    if (dmarc.found) {
        if (dmarcRecords.length > 1) {
            findings.push({
                severity: 'error',
                code: 'dmarc-multiple',
                message: `${dmarcRecords.length} DMARC records under ${dmarcName}; per RFC 7489 §6.6.3 the domain's policy is then treated as if none were published`,
            });
        }
        if (!dmarc.versionFirst) {
            findings.push({
                severity: 'warning',
                code: 'dmarc-version-not-first',
                message: 'the "v=DMARC1" tag is not first, so RFC 7489 §6.6.1 says the record must be ignored',
            });
        }
        if (dmarc.policy === undefined) {
            findings.push({ severity: 'error', code: 'dmarc-policy-missing', message: 'no "p" tag: p is required, so this record is unusable' });
        }
        else if (!['none', 'quarantine', 'reject'].includes(dmarc.policy)) {
            findings.push({
                severity: 'error',
                code: 'dmarc-policy-invalid',
                message: `"p=${dmarc.policy}" is not one of none / quarantine / reject`,
            });
        }
        else if (dmarc.policy === 'none') {
            findings.push({
                severity: 'info',
                code: 'dmarc-policy-none',
                message: '"p=none" only asks receivers to report; nothing is enforced for failed mail',
            });
        }
        if (dmarc.percentage !== undefined && dmarc.percentage < DMARC_DEFAULT_PCT) {
            findings.push({
                severity: 'info',
                code: 'dmarc-pct-partial',
                message: `pct=${dmarc.percentage}: the policy applies to that share of failing mail only, the rest is treated as p=none`,
            });
        }
    }
    else if (dmarcError === undefined) {
        findings.push({
            severity: 'warning',
            code: 'dmarc-missing',
            message: `no DMARC record at ${dmarcName} — receivers have no instruction for mail that fails SPF/DKIM alignment`,
        });
    }
    else {
        findings.push({ severity: 'error', code: 'dmarc-error', message: `TXT lookup for ${dmarcName} failed: ${dmarcError}` });
    }
    // ---- DKIM ---------------------------------------------------------------
    const dkim = [];
    for (const selector of selectors) {
        const name = `${selector}._domainkey.${domain}`;
        const report = { selector, name, found: false, revoked: false };
        try {
            const records = txtRecords(await lookup(name, 'TXT'));
            const keyRecord = records.find((record) => /(?:^|;)\s*p\s*=/i.test(record));
            if (keyRecord === undefined) {
                report.error = 'no TXT record carrying a "p=" public key';
                findings.push({ severity: 'warning', code: 'dkim-missing', message: `selector "${selector}": no key at ${name}` });
            }
            else {
                const tags = parseDkimRecord(keyRecord);
                report.found = true;
                report.revoked = (tags.p ?? '').trim() === '';
                if (tags.k !== undefined)
                    report.keyType = tags.k;
                if (report.revoked) {
                    findings.push({
                        severity: 'warning',
                        code: 'dkim-revoked',
                        message: `selector "${selector}": the key record has an empty "p=" tag, which means the key was revoked`,
                    });
                }
            }
        }
        catch (error) {
            if (isMissingRecordError(error)) {
                findings.push({ severity: 'warning', code: 'dkim-missing', message: `selector "${selector}": no key at ${name}` });
            }
            else {
                report.error = errorText(error);
                findings.push({ severity: 'error', code: 'dkim-error', message: `TXT lookup for ${name} failed: ${report.error}` });
            }
        }
        dkim.push(report);
    }
    if (selectors.length === 0) {
        findings.push({
            severity: 'info',
            code: 'dkim-not-checked',
            message: 'DKIM selectors cannot be discovered from the domain name alone; pass dkimSelectors (e.g. the selector from a mail header "s=") to probe them',
        });
    }
    const ordered = findings
        .map((finding, index) => ({ finding, index }))
        .sort((left, right) => (severityRank(left.finding.severity) === severityRank(right.finding.severity)
        ? left.index - right.index
        : severityRank(left.finding.severity) - severityRank(right.finding.severity)))
        .map((entry) => entry.finding);
    const result = {
        domain,
        mailAccepted,
        mx,
        nullMx,
        implicitMx,
        fallbackAddresses,
        spf,
        dmarc,
        dkim,
        findings: ordered,
    };
    if (mxError !== undefined)
        result.mxError = mxError;
    if (spfError === undefined && dmarcError === undefined) {
        result.note = 'DNS records only: DKIM signing, PTR/reputation and actual delivery were not exercised';
    }
    return result;
}
//# sourceMappingURL=email.js.map