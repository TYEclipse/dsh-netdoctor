/**
 * Tests for the DNS propagation probe: agreement tallying across resolvers,
 * honest failure/timeout reporting, fingerprint stability and input validation.
 * All resolvers are fakes — the suite never touches the network.
 *
 * ORACLE: test/oracle/anchors.py
 */

import { describe, expect, it } from 'vitest'
import { answerFingerprint, dnsPropagation, DEFAULT_RESOLVERS } from '../src/propagation.ts'
import type { DnsAnswer, DnsRecordType, DnsResult } from '../src/dns.ts'

/** One resolver's scripted behaviour: records, a thrown error, or a promise that never settles. */
type Entry = DnsAnswer[] | Error | 'hang'

function answersFor(addresses: string[], ttl = 300): DnsAnswer[] {
  return addresses.map((address) => ({ name: 'example.com', type: 'A', ttl, data: { address } }))
}

const SAME = answersFor(['93.184.216.34'])
const NEW = answersFor(['93.184.216.99'])

function lookupFrom(table: Record<string, Entry>) {
  return async (host: string, record: DnsRecordType, server: string | undefined): Promise<DnsResult> => {
    const key = server ?? 'system'
    const entry = table[key]
    if (entry === undefined) throw new Error(`test bug: no fixture for resolver ${key}`)
    if (entry === 'hang') return new Promise<DnsResult>(() => {})
    if (entry instanceof Error) throw entry
    return { host, record, server: key, answers: entry }
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

const THREE = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

describe('dnsPropagation', () => {
  it('reports agreement when every resolver returns the same records', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({ '1.1.1.1': SAME, '8.8.8.8': SAME, '9.9.9.9': SAME }),
    })
    expect(result.resolvers).toBe(3)
    expect(result.responded).toBe(3)
    expect(result.failed).toBe(0)
    expect(result.groups).toHaveLength(1)
    expect(result.consistent).toBe(true)
    expect(result.consensus?.resolvers).toHaveLength(3)
    expect(result.note).toBeUndefined()
    expect(result.probes.every((probe) => probe.status === 'ok')).toBe(true)
    assertNoUndefined(result)
  })

  it('splits disagreeing resolvers into groups ordered by size', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({ '1.1.1.1': SAME, '8.8.8.8': SAME, '9.9.9.9': NEW }),
    })
    expect(result.groups.map((group) => group.resolvers.length)).toEqual([2, 1])
    expect(result.groups[0]?.resolvers).toEqual(['1.1.1.1', '8.8.8.8'])
    expect(result.consistent).toBe(false)
    expect(result.consensus?.resolvers).toHaveLength(2)
    expect(result.note).toContain('disagree')
  })

  it('counts a resolver that returns the same records with a different TTL as agreeing', async () => {
    // Caches legitimately hand out different TTLs; only the record content is compared.
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({
        '1.1.1.1': answersFor(['93.184.216.34'], 300),
        '8.8.8.8': answersFor(['93.184.216.34'], 42),
        '9.9.9.9': answersFor(['93.184.216.34'], 3600),
      }),
    })
    expect(result.groups).toHaveLength(1)
    expect(result.consistent).toBe(true)
  })

  it('treats the answer order inside one reply as irrelevant', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({
        '1.1.1.1': answersFor(['1.1.1.1', '2.2.2.2']),
        '8.8.8.8': answersFor(['2.2.2.2', '1.1.1.1']),
        '9.9.9.9': answersFor(['2.2.2.2', '1.1.1.1']),
      }),
    })
    expect(result.groups).toHaveLength(1)
    expect(result.consistent).toBe(true)
  })

  it('reports a failing resolver as failed instead of folding it into the majority', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({ '1.1.1.1': SAME, '8.8.8.8': SAME, '9.9.9.9': new Error('SERVFAIL') }),
    })
    expect(result.responded).toBe(2)
    expect(result.failed).toBe(1)
    expect(result.groups).toHaveLength(1)
    expect(result.consistent).toBe(true)
    expect(result.note).toContain('partial')
    const failed = result.probes.find((probe) => probe.status === 'error')
    expect(failed?.error).toContain('SERVFAIL')
    expect(failed?.timedOut).toBeUndefined()
  })

  it('flags a resolver that never answers, and never invents a consensus', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      timeoutMs: 120,
      lookup: lookupFrom({ '1.1.1.1': SAME, '8.8.8.8': 'hang', '9.9.9.9': new Error('EHOSTUNREACH') }),
    })
    expect(result.responded).toBe(1)
    expect(result.failed).toBe(2)
    expect(result.consistent).toBe(true)
    expect(result.consensus).toBeUndefined()
    const hung = result.probes.find((probe) => probe.server === '8.8.8.8')
    expect(hung?.timedOut).toBe(true)
    expect(hung?.error).toContain('no answer')
  })

  it('reports no agreement when nobody answers', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: THREE,
      lookup: lookupFrom({ '1.1.1.1': new Error('ETIMEDOUT'), '8.8.8.8': new Error('ETIMEDOUT'), '9.9.9.9': new Error('ETIMEDOUT') }),
    })
    expect(result.responded).toBe(0)
    expect(result.failed).toBe(3)
    expect(result.groups).toHaveLength(0)
    expect(result.consistent).toBe(false)
    expect(result.consensus).toBeUndefined()
    expect(result.note).toContain('no resolver answered')
  })

  it('falls back to the built-in resolver set', async () => {
    const asked: (string | undefined)[] = []
    const result = await dnsPropagation('example.com', 'A', {
      lookup: async (host, record, server) => {
        asked.push(server)
        return { host, record, server: server ?? 'system', answers: SAME }
      },
    })
    expect(result.resolvers).toBe(DEFAULT_RESOLVERS.length)
    expect(asked).toEqual(DEFAULT_RESOLVERS.map((resolver) => resolver.server))
  })

  it('labels caller-supplied resolvers by their address', async () => {
    const result = await dnsPropagation('example.com', 'A', {
      resolvers: ['8.8.8.8', '1.1.1.1'],
      lookup: lookupFrom({ '8.8.8.8': SAME, '1.1.1.1': SAME }),
    })
    expect(result.resolvers).toBe(2)
    expect(result.probes.map((probe) => probe.label)).toEqual(['8.8.8.8', '1.1.1.1'])
  })

  it('validates host, resolvers and timeout', async () => {
    await expect(dnsPropagation('bad host;', 'A', { resolvers: ['1.1.1.1'] })).rejects.toThrow()
    await expect(dnsPropagation('example.com', 'A', { resolvers: ['dns.example.com'] })).rejects.toThrow(/hostnames/)
    await expect(dnsPropagation('example.com', 'A', { resolvers: ['0'] })).rejects.toThrow()
    await expect(
      dnsPropagation('example.com', 'A', { resolvers: Array.from({ length: 11 }, (_value, index) => `10.0.0.${index}`) }),
    ).rejects.toThrow(/at most 10/)
    await expect(dnsPropagation('example.com', 'A', { timeoutMs: 10, resolvers: ['1.1.1.1'] })).rejects.toThrow()
  })
})

describe('answerFingerprint', () => {
  it('ignores answer order, key order and TTL, but not the record values', () => {
    const one = answersFor(['1.1.1.1'])
    const two = answersFor(['2.2.2.2'])
    expect(answerFingerprint([...two, ...one])).toBe(answerFingerprint([...one, ...two]))

    const mxA: DnsAnswer = { name: 'example.com', type: 'MX', ttl: 0, data: { exchange: 'mail.example.com', priority: 10 } }
    const mxB: DnsAnswer = { name: 'example.com', type: 'MX', ttl: 0, data: { priority: 10, exchange: 'mail.example.com' } }
    expect(answerFingerprint([mxA])).toBe(answerFingerprint([mxB]))

    expect(answerFingerprint(answersFor(['1.1.1.1'], 300))).toBe(answerFingerprint(answersFor(['1.1.1.1'], 60)))
    expect(answerFingerprint(answersFor(['1.1.1.1']))).not.toBe(answerFingerprint(answersFor(['1.1.1.2'])))
    expect(answerFingerprint([])).toBe('')
  })
})
