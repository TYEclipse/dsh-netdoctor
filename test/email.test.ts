/**
 * Tests for the mail-readiness probe: MX ordering and the null-MX signal, the
 * SPF DNS-lookup budget and final qualifier, DMARC tags, DKIM selector probes,
 * and the honest failure paths (a failed lookup is a failure, never "no
 * records"). All DNS answers are fakes — the suite never touches the network.
 *
 * ORACLE: test/oracle/anchors.py
 */

import { describe, expect, it } from 'vitest'
import {
  assembleTxt,
  classifySpfTerm,
  DMARC_DEFAULT_PCT,
  emailDns,
  isDmarcRecord,
  isSpfRecord,
  MAX_DKIM_SELECTORS,
  parseDkimRecord,
  parseDmarcRecord,
  parseSpfRecord,
  SPF_LOOKUP_LIMIT,
  type EmailLookup,
} from '../src/email.ts'
import type { DnsAnswer, DnsRecordType, DnsResult } from '../src/dns.ts'

/** One MX answer list: [exchange, priority] pairs. */
function mxAnswers(host: string, records: Array<[string, number]>): DnsAnswer[] {
  return records.map(([exchange, priority]) => ({ name: host, type: 'MX', ttl: 0, data: { exchange, priority } }))
}

/** One TXT answer per entry; each entry is that record's character-strings. */
function txtAnswers(host: string, records: string[][]): DnsAnswer[] {
  return records.map((entries) => ({ name: host, type: 'TXT', ttl: 0, data: { entries } }))
}

function aAnswers(host: string, addresses: string[]): DnsAnswer[] {
  return addresses.map((address) => ({ name: host, type: 'A', ttl: 0, data: { address } }))
}

/**
 * Fake resolver: keyed by "<TYPE>:<host>". A missing key throws the way node's
 * resolver does for a name with no such record, so "not found" and "lookup
 * failed" are exercised separately.
 */
function lookupFrom(table: Record<string, DnsAnswer[]>, failures: Record<string, string> = {}): EmailLookup {
  return async (host: string, record: DnsRecordType): Promise<DnsResult> => {
    const key = `${record}:${host}`
    const failure = failures[key]
    if (failure !== undefined) throw new Error(failure)
    const answers = table[key]
    if (answers === undefined) throw new Error(`ENOTFOUND ${host}`)
    return { host, record, server: 'system', answers }
  }
}

function assertNoUndefined(value: unknown, path = 'root'): void {
  if (value === undefined) throw new Error(`undefined value at ${path}`)
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoUndefined(item, `${path}[${index}]`))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) assertNoUndefined(item, `${path}.${key}`)
  }
}

const HEALTHY = lookupFrom({
  'MX:test': mxAnswers('test', [['mx1.mail.test', 20], ['mx2.mail.test', 10]]),
  'TXT:test': txtAnswers('test', [
    ['v=spf1 a mx include:_spf.test ip4:192.0.2.0/24 exists:chk.test -all'],
    ['google-site-verification=abc'],
  ]),
  'TXT:_dmarc.test': txtAnswers('_dmarc.test', [
    ['v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@test,mailto:b@test; ruf=mailto:f@test'],
  ]),
  'TXT:sel1._domainkey.test': txtAnswers('sel1._domainkey.test', [['v=DKIM1; k=rsa; p=MIIBIjANBg']]),
  'A:test': aAnswers('test', ['192.0.2.10']),
})

const PERMISSIVE = lookupFrom({
  'MX:test': mxAnswers('test', [['mx1.mail.test', 10]]),
  'TXT:test': txtAnswers('test', [
    ['v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test a mx ptr exists:z.test +all'],
    ['v=spf1 -all'],
  ]),
  'TXT:_dmarc.test': txtAnswers('_dmarc.test', [['v=DMARC1; p=none; pct=100']]),
})

const NULL_MX = lookupFrom({
  'MX:test': mxAnswers('test', [['.', 0]]),
  'TXT:test': txtAnswers('test', []),
  'TXT:_dmarc.test': txtAnswers('_dmarc.test', []),
  'A:test': aAnswers('test', ['192.0.2.10']),
})

const NO_MX = lookupFrom({
  'MX:test': mxAnswers('test', []),
  'TXT:test': txtAnswers('test', [['v=spf1 redirect=_spf.test']]),
  'A:test': aAnswers('test', ['192.0.2.11', '192.0.2.12']),
})

const ODD_TERMS = lookupFrom({
  'MX:test': mxAnswers('test', [['mx1.mail.test', 10]]),
  'TXT:test': txtAnswers('test', [['v=spf1 mx:mail.test ?all foo:bar a:host.test/24']]),
  'TXT:_dmarc.test': txtAnswers('_dmarc.test', [['v=DMARC1; p=quarantine; p=reject']]),
  'TXT:revoked._domainkey.test': txtAnswers('revoked._domainkey.test', [['v=DKIM1; k=rsa; p=']]),
  'TXT:absent._domainkey.test': txtAnswers('absent._domainkey.test', []),
})

/** One TXT record split into two character-strings, as a 255-byte split would arrive. */
const MULTI_STRING = lookupFrom({
  'MX:test': mxAnswers('test', [['mx1.mail.test', 10]]),
  'TXT:test': txtAnswers('test', [['v=spf1 include:_spf.te', 'st -all']]),
  'TXT:_dmarc.test': txtAnswers('_dmarc.test', [['v=DMARC1;p=reject']]),
})

describe('emailDns — a healthy domain', () => {
  it('orders MX by priority and reports mail as accepted', async () => {
    const result = await emailDns('test', { dkimSelectors: ['sel1'], lookup: HEALTHY })
    expect(result.mx.map((record) => `${record.priority}:${record.exchange}`)).toEqual(['10:mx2.mail.test', '20:mx1.mail.test'])
    expect(result.nullMx).toBe(false)
    expect(result.implicitMx).toBe(false)
    expect(result.mailAccepted).toBe(true)
    expect(result.fallbackAddresses).toEqual([])
    expect(result.mxError).toBeUndefined()
  })

  it('counts only the DNS-querying SPF terms and finds the final qualifier', async () => {
    const { spf } = await emailDns('test', { dkimSelectors: ['sel1'], lookup: HEALTHY })
    expect(spf.found).toBe(true)
    expect(spf.records).toHaveLength(1)
    expect(spf.terms).toHaveLength(6)
    expect(spf.dnsLookups).toBe(4)
    expect(spf.lookupLimit).toBe(10)
    expect(spf.exceedsLimit).toBe(false)
    expect(spf.allQualifier).toBe('-')
    expect(spf.allIsLast).toBe(true)
    expect(spf.includes).toEqual(['_spf.test'])
    expect(spf.redirect).toBeUndefined()
    expect(spf.unknownTerms).toEqual([])
    expect(spf.multiple).toBe(false)
  })

  it('parses DMARC tags, reporting URIs and the partial percentage', async () => {
    const { dmarc } = await emailDns('test', { dkimSelectors: ['sel1'], lookup: HEALTHY })
    expect(dmarc.found).toBe(true)
    expect(dmarc.name).toBe('_dmarc.test')
    expect(dmarc.policy).toBe('reject')
    expect(dmarc.subdomainPolicy).toBe('quarantine')
    expect(dmarc.percentage).toBe(50)
    expect(dmarc.reportingUris).toHaveLength(2)
    expect(dmarc.forensicUris).toHaveLength(1)
    expect(dmarc.versionFirst).toBe(true)
    expect(dmarc.usable).toBe(true)
    expect(dmarc.duplicateTags).toEqual([])
    expect(dmarc.tags.v).toBe('DMARC1')
  })

  it('probes the named DKIM selector and reports the key type', async () => {
    const { dkim } = await emailDns('test', { dkimSelectors: ['sel1'], lookup: HEALTHY })
    expect(dkim).toHaveLength(1)
    expect(dkim[0]?.name).toBe('sel1._domainkey.test')
    expect(dkim[0]?.found).toBe(true)
    expect(dkim[0]?.revoked).toBe(false)
    expect(dkim[0]?.keyType).toBe('rsa')
  })

  it('reports only the partial-percentage note when everything else is sound', async () => {
    const result = await emailDns('test', { dkimSelectors: ['sel1'], lookup: HEALTHY })
    expect(result.findings.map((finding) => finding.code)).toEqual(['dmarc-pct-partial'])
    expect(result.findings[0]?.severity).toBe('info')
    expect(result.note).toContain('not exercised')
    assertNoUndefined(result)
  })
})

describe('emailDns — misconfigurations', () => {
  it('flags duplicate SPF records, an over-budget record and a permissive all', async () => {
    const result = await emailDns('test', { lookup: PERMISSIVE })
    expect(result.spf.records).toHaveLength(2)
    expect(result.spf.multiple).toBe(true)
    expect(result.spf.terms).toHaveLength(12)
    expect(result.spf.dnsLookups).toBe(11)
    expect(result.spf.exceedsLimit).toBe(true)
    expect(result.spf.allQualifier).toBe('+')
    expect(result.spf.allIsLast).toBe(true)
    expect(result.spf.includes).toHaveLength(7)
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'spf-multiple',
      'spf-too-many-lookups',
      'spf-permissive',
      'dmarc-policy-none',
      'dkim-not-checked',
    ])
    expect(result.findings.map((finding) => finding.severity)).toEqual(['error', 'warning', 'warning', 'info', 'info'])
    assertNoUndefined(result)
  })

  it('treats a null MX as "this domain accepts no mail"', async () => {
    const result = await emailDns('test', { lookup: NULL_MX })
    expect(result.mx.map((record) => `${record.priority}:${record.exchange}`)).toEqual(['0:.'])
    expect(result.nullMx).toBe(true)
    expect(result.implicitMx).toBe(false)
    expect(result.mailAccepted).toBe(false)
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'spf-missing',
      'dmarc-missing',
      'mx-null',
      'dkim-not-checked',
    ])
    assertNoUndefined(result)
  })

  it('recognises the null MX whether the root is spelled "." or left empty', async () => {
    // node's resolver hands back an empty exchange for the root; the record on
    // the wire is "0 .", so both spellings must mean the same thing.
    const empty = await emailDns('test', {
      lookup: lookupFrom({ 'MX:test': mxAnswers('test', [['', 0]]), 'TXT:test': txtAnswers('test', []), 'TXT:_dmarc.test': txtAnswers('_dmarc.test', []) }),
    })
    expect(empty.nullMx).toBe(true)
    expect(empty.mailAccepted).toBe(false)
    // A single root MX that is *not* priority 0 is not a null MX (RFC 7505).
    const wrongPriority = await emailDns('test', {
      lookup: lookupFrom({ 'MX:test': mxAnswers('test', [['.', 10]]), 'TXT:test': txtAnswers('test', []), 'TXT:_dmarc.test': txtAnswers('_dmarc.test', []) }),
    })
    expect(wrongPriority.nullMx).toBe(false)
    assertNoUndefined(empty)
  })

  it('falls back to A records when MX is absent, and says so', async () => {
    const result = await emailDns('test', { lookup: NO_MX })
    expect(result.mx).toEqual([])
    expect(result.implicitMx).toBe(true)
    expect(result.fallbackAddresses).toEqual(['192.0.2.11', '192.0.2.12'])
    expect(result.mailAccepted).toBe(true)
    expect(result.spf.terms).toHaveLength(1)
    expect(result.spf.dnsLookups).toBe(1)
    expect(result.spf.redirect).toBe('_spf.test')
    expect(result.spf.allQualifier).toBeUndefined()
    expect(result.spf.allIsLast).toBe(false)
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'mx-missing',
      'dmarc-missing',
      'spf-no-all',
      'dkim-not-checked',
    ])
    assertNoUndefined(result)
  })

  it('reports unknown terms, a non-final all, duplicate DMARC tags and a revoked key', async () => {
    const result = await emailDns('test', { dkimSelectors: ['revoked', 'absent'], lookup: ODD_TERMS })
    expect(result.spf.terms).toHaveLength(4)
    expect(result.spf.dnsLookups).toBe(2)
    expect(result.spf.allQualifier).toBe('?')
    expect(result.spf.allIsLast).toBe(false)
    expect(result.spf.unknownTerms).toEqual(['foo:bar'])
    // The first occurrence of a repeated tag wins (RFC 7489 §6.4).
    expect(result.dmarc.policy).toBe('quarantine')
    expect(result.dmarc.duplicateTags).toEqual(['p'])
    expect(result.dmarc.percentage).toBeUndefined()
    expect(result.dkim.map((report) => report.found)).toEqual([true, false])
    expect(result.dkim[0]?.revoked).toBe(true)
    expect(result.dkim[1]?.error).toContain('p=')
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'spf-permissive',
      'spf-all-not-last',
      'spf-unknown-term',
      'dkim-revoked',
      'dkim-missing',
    ])
    assertNoUndefined(result)
  })

  it('joins the character-strings of one split TXT record without a separator', async () => {
    const result = await emailDns('test', { lookup: MULTI_STRING })
    expect(result.spf.selected).toBe('v=spf1 include:_spf.test -all')
    expect(result.spf.terms).toHaveLength(2)
    expect(result.spf.dnsLookups).toBe(1)
    expect(result.spf.includes).toEqual(['_spf.test'])
    expect(result.spf.allQualifier).toBe('-')
    expect(result.findings.map((finding) => finding.code)).toEqual(['dkim-not-checked'])
    assertNoUndefined(result)
  })
})

describe('emailDns — failures are reported, not smoothed over', () => {
  it('reports a name that resolves to nothing as "not found", not as a lookup error', async () => {
    const result = await emailDns('test', { lookup: lookupFrom({}) })
    expect(result.mx).toEqual([])
    expect(result.mxError).toBeUndefined()
    expect(result.mailAccepted).toBe(false)
    expect(result.spf.found).toBe(false)
    expect(result.spf.error).toBeUndefined()
    expect(result.dmarc.found).toBe(false)
    expect(result.dmarc.error).toBeUndefined()
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'domain-not-found',
      'spf-missing',
      'dmarc-missing',
      'dkim-not-checked',
    ])
    assertNoUndefined(result)
  })

  it('reports transport failures as errors instead of "no records"', async () => {
    const failing = lookupFrom({}, { 'MX:test': 'ETIMEOUT', 'TXT:test': 'ETIMEOUT', 'TXT:_dmarc.test': 'ETIMEOUT' })
    const result = await emailDns('test', { lookup: failing })
    expect(result.mx).toEqual([])
    expect(result.mxError).toContain('ETIMEOUT')
    expect(result.implicitMx).toBe(false)
    expect(result.mailAccepted).toBe(false)
    expect(result.spf.found).toBe(false)
    expect(result.spf.error).toContain('ETIMEOUT')
    expect(result.dmarc.found).toBe(false)
    expect(result.dmarc.error).toContain('ETIMEOUT')
    expect(result.note).toBeUndefined()
    expect(result.findings.map((finding) => finding.code)).toEqual([
      'mx-error',
      'spf-error',
      'dmarc-error',
      'dkim-not-checked',
    ])
    expect(result.findings.filter((finding) => finding.severity === 'error')).toHaveLength(3)
    assertNoUndefined(result)
  })

  it('validates the domain and the selector list', async () => {
    await expect(emailDns('bad host;', { lookup: HEALTHY })).rejects.toThrow()
    await expect(emailDns('test', { dkimSelectors: ['has space'], lookup: HEALTHY })).rejects.toThrow(/selector/)
    await expect(
      emailDns('test', {
        dkimSelectors: Array.from({ length: MAX_DKIM_SELECTORS + 1 }, (_value, index) => `s${index}`),
        lookup: HEALTHY,
      }),
    ).rejects.toThrow(/at most 5/)
  })

  it('probes each distinct selector once, keeping the caller\'s order', async () => {
    const asked: string[] = []
    const result = await emailDns('test', {
      dkimSelectors: ['s2', 's1', 's2'],
      lookup: async (host, record) => {
        asked.push(`${record}:${host}`)
        if (record === 'MX') return { host, record, server: 'system', answers: mxAnswers('test', [['mx1.mail.test', 10]]) }
        if (host.startsWith('s1._domainkey')) return { host, record, server: 'system', answers: txtAnswers(host, [['v=DKIM1; p=AAAA']]) }
        throw new Error(`ENOTFOUND ${host}`)
      },
    })
    expect(asked.filter((key) => key.startsWith('TXT:s'))).toEqual(['TXT:s2._domainkey.test', 'TXT:s1._domainkey.test'])
    expect(result.dkim.map((report) => report.selector)).toEqual(['s2', 's1'])
    expect(result.dkim.map((report) => report.found)).toEqual([false, true])
    assertNoUndefined(result)
  })
})

describe('email parsing primitives', () => {
  it('recognises version tags only at the start of a record', () => {
    expect(isSpfRecord('v=spf1 -all')).toBe(true)
    expect(isSpfRecord('V=SPF1 -all')).toBe(true)
    expect(isSpfRecord('v=spf10 -all')).toBe(false)
    expect(isSpfRecord('google-site-verification=abc')).toBe(false)
    expect(isDmarcRecord('v=DMARC1; p=reject')).toBe(true)
    expect(isDmarcRecord('v=DMARC1;p=reject')).toBe(true)
    expect(isDmarcRecord('p=reject; v=DMARC1')).toBe(false)
  })

  it('joins split character-strings with nothing between them', () => {
    expect(assembleTxt(['v=spf1 include:_spf.te', 'st -all'])).toBe('v=spf1 include:_spf.test -all')
    expect(assembleTxt(['only-one'])).toBe('only-one')
    expect(assembleTxt([])).toBe('')
  })

  it('classifies the DNS-querying SPF terms from the RFC list', () => {
    const table: Array<[string, number]> = [
      ['include:x.test', 1], ['exists:x.test', 1], ['a', 1], ['a:x.test/24', 1], ['mx', 1],
      ['mx:x.test', 1], ['ptr', 1], ['ptr:x.test', 1], ['redirect=x.test', 1],
      ['ip4:192.0.2.1', 0], ['ip6:2001:db8::1', 0], ['all', 0], ['-all', 0], ['exp=x.test', 0],
    ]
    for (const [term, expected] of table) {
      const verdict = classifySpfTerm(term)
      expect(verdict.dns, term).toBe(expected === 1)
      expect(verdict.unknown, term).toBe(false)
    }
    expect(classifySpfTerm('foo:bar').unknown).toBe(true)
    expect(classifySpfTerm('~all').kind).toBe('all')
  })

  it('returns undefined for a string that is not an SPF record', () => {
    expect(parseSpfRecord('google-site-verification=abc')).toBeUndefined()
    expect(parseSpfRecord('v=spf1').terms).toEqual([])
  })

  it('treats version-first as a position rule, not a substring match', () => {
    expect(parseDmarcRecord('v=DMARC1; p=reject').versionFirst).toBe(true)
    expect(parseDmarcRecord('p=reject; v=DMARC1').versionFirst).toBe(false)
    expect(parseDmarcRecord('v=DMARC1; p=reject; p=none').tags.p).toBe('reject')
    expect(parseDmarcRecord('v=DMARC1; p=reject; p=none').duplicateTags).toEqual(['p'])
  })

  it('reads DKIM key records into lower-cased tags', () => {
    expect(parseDkimRecord('v=DKIM1; K=RSA; p=AAAA')).toEqual({ v: 'DKIM1', k: 'RSA', p: 'AAAA' })
    expect(parseDkimRecord('v=DKIM1; p=')).toEqual({ v: 'DKIM1', p: '' })
    expect(parseDkimRecord('')).toEqual({})
  })

  it('keeps the RFC constants the report is built on', () => {
    expect(SPF_LOOKUP_LIMIT).toBe(10)
    expect(DMARC_DEFAULT_PCT).toBe(100)
    expect(MAX_DKIM_SELECTORS).toBe(5)
  })
})
