/**
 * Tests for the WHOIS probe: referral parsing, summary extraction, and the
 * raw TCP 43 socket path against a local fixture server (fully offline).
 */

import { createServer } from 'node:net'
import type { AddressInfo, Server } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { fallbackWhoisServer, parseIanaReferral, parseWhoisSummary, rawWhoisQuery, tldOf, whoisLookup } from '../src/whois.ts'

/**
 * Walk a result tree and assert no live `undefined` values exist — the
 * dsh-tools output gate rejects any key whose value is undefined even when
 * JSON.stringify would silently drop it (lossless-JSON discipline, R7).
 */
function assertNoUndefined(value: unknown, path = 'root'): void {
  if (value === undefined) throw new Error(`undefined value at ${path}`)
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoUndefined(item, `${path}[${index}]`))
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) assertNoUndefined(item, `${path}.${key}`)
  }
}

const COM_FIXTURE = [
  '   Domain Name: EXAMPLE.COM',
  '   Registry Domain ID: 2336799_DOMAIN_COM-VRSN',
  '   Registrar WHOIS Server: whois.iana.org',
  '   Registrar URL: http://res-dom.iana.org',
  '   Updated Date: 2025-08-13T17:11:24Z',
  '   Creation Date: 1995-08-14T04:00:00Z',
  '   Registry Expiry Date: 2026-08-13T04:00:00Z',
  '   Registrar: RESERVED-Internet Assigned Numbers Authority',
  '   Registrar IANA ID: 376',
  '   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited',
  '   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited',
  '   Name Server: A.IANA-SERVERS.NET',
  '   Name Server: B.IANA-SERVERS.NET',
  '   DNSSEC: signedDelegation',
  '',
].join('\n')

const ORG_FIXTURE = [
  'Domain Name: example.org',
  'Registry Domain ID: 8f69de43f21e4b7a9e47db0c4a2f2a2b-LROR',
  'Registrar WHOIS Server: whois.pir.org',
  'Registrar URL: http://www.whois.pir.org/',
  'Updated Date: 2025-10-01T10:00:00Z',
  'Creation Date: 1999-01-01T00:00:00Z',
  'Registry Expiry Date: 2026-01-01T00:00:00Z',
  'Registrar: Internet Corporation for Assigned Names and Numbers',
  'Registrar IANA ID: 9999',
  'Domain Status: clientDeleteProhibited',
  'Name Server: NS1.EXAMPLE.ORG',
  'Name Server: NS2.EXAMPLE.ORG',
  '',
].join('\n')

const IANA_REFERRAL_FIXTURE = [
  '% IANA WHOIS server',
  '% for more information on IANA, visit http://www.iana.org',
  '% This query returned 1 object',
  '',
  'refer:        whois.verisign-grs.com',
  '',
  'domain:       EXAMPLE.COM',
  '',
].join('\n')

describe('parseIanaReferral', () => {
  it('extracts the refer line', () => {
    expect(parseIanaReferral(IANA_REFERRAL_FIXTURE)).toBe('whois.verisign-grs.com')
  })

  it('returns undefined when no referral is present', () => {
    expect(parseIanaReferral('No match for "ZZZZZZ.COM".')).toBeUndefined()
  })
})

describe('fallbackWhoisServer', () => {
  it('maps common TLDs to their registries', () => {
    expect(fallbackWhoisServer('example.com')).toBe('whois.verisign-grs.com')
    expect(fallbackWhoisServer('example.org')).toBe('whois.pir.org')
    expect(fallbackWhoisServer('example.io')).toBe('whois.nic.io')
    expect(fallbackWhoisServer('blog.example.co.uk')).toBe('whois.nic.uk')
  })

  it('routes IP literals to ARIN', () => {
    expect(fallbackWhoisServer('8.8.8.8')).toBe('whois.arin.net')
    expect(fallbackWhoisServer('2001:4860:4860::8888')).toBe('whois.arin.net')
  })

  it('returns undefined for unknown TLDs', () => {
    expect(fallbackWhoisServer('example.unknownzz')).toBeUndefined()
  })

  it('extracts the TLD case-insensitively', () => {
    expect(tldOf('EXAMPLE.COM')).toBe('com')
    expect(tldOf('sub.example.org')).toBe('org')
  })
})

describe('parseWhoisSummary', () => {
  it('parses a Verisign-style .com response', () => {
    const summary = parseWhoisSummary(COM_FIXTURE)
    expect(summary.registrar).toBe('RESERVED-Internet Assigned Numbers Authority')
    expect(summary.createdDate).toBe('1995-08-14T04:00:00Z')
    expect(summary.updatedDate).toBe('2025-08-13T17:11:24Z')
    expect(summary.expiryDate).toBe('2026-08-13T04:00:00Z')
    expect(summary.statuses).toContain('clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited')
    expect(summary.statuses).toHaveLength(2)
    expect(summary.nameServers).toEqual(['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET'])
  })

  it('parses a .org-style response', () => {
    const summary = parseWhoisSummary(ORG_FIXTURE)
    expect(summary.registrar).toBe('Internet Corporation for Assigned Names and Numbers')
    expect(summary.expiryDate).toBe('2026-01-01T00:00:00Z')
    expect(summary.statuses).toEqual(['clientDeleteProhibited'])
    expect(summary.nameServers).toEqual(['NS1.EXAMPLE.ORG', 'NS2.EXAMPLE.ORG'])
  })

  it('returns an empty summary for no-match responses', () => {
    const summary = parseWhoisSummary('No match for "ZZZZZZZZ.COM".')
    expect(summary.registrar).toBeUndefined()
    expect(summary.createdDate).toBeUndefined()
    expect(summary.expiryDate).toBeUndefined()
    expect(summary.statuses).toEqual([])
    expect(summary.nameServers).toEqual([])
  })
})

describe('rawWhoisQuery', () => {
  let server: Server
  let port = 0
  let received = ''

  beforeAll(async () => {
    server = createServer((socket) => {
      socket.on('data', (chunk: Buffer) => {
        received += chunk.toString('utf8')
        socket.end(COM_FIXTURE)
      })
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = (server.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  it('sends the query line and collects the full response', async () => {
    const text = await rawWhoisQuery('127.0.0.1', 'example.com', 3_000, port)
    expect(text).toContain('Domain Name: EXAMPLE.COM')
    expect(received).toBe('example.com\r\n')
  })

  it('rejects when the server refuses the connection', async () => {
    await expect(rawWhoisQuery('127.0.0.1', 'example.com', 1_000, port + 1)).rejects.toThrow(/failed/)
  })
})

describe('whoisLookup', () => {
  it('reports a graceful error result when the server is unreachable', async () => {
    const result = await whoisLookup('example.com', '127.0.0.1', 2_000)
    expect(result.domain).toBe('example.com')
    expect(result.server).toBe('127.0.0.1')
    expect(result.error).toContain('failed')
    expect(result.raw).toBe('')
    expect(result.rawTruncated).toBe(false)
    expect(result.summary.statuses).toEqual([])
    assertNoUndefined(result)
  })

  it('rejects invalid domain input', async () => {
    await expect(whoisLookup('not a domain!!', undefined, 2_000)).rejects.toThrow()
  })

  it('never leaves live undefined values on success results either', () => {
    // Guard on the shape produced by `build`: every optional field must be
    // absent (not undefined) when missing.
    const text = 'No match for "ZZZZZZZZ.COM".'
    const parsed = parseWhoisSummary(text)
    expect(parsed.registrar).toBeUndefined()
    assertNoUndefined(parsed)
  })
})
