/**
 * Tests for tool definition assembly, config resolution and the text renderers.
 *
 * ORACLE: test/oracle/anchors.py
 */

import { describe, expect, it } from 'vitest'
import { resolveConfig } from '../src/index.ts'
import { buildNetdoctorTools } from '../src/tools.ts'

describe('resolveConfig', () => {
  it('applies every default', () => {
    const resolved = resolveConfig({})
    expect(resolved).toEqual({
      timeoutMs: 3_000,
      pingCount: 4,
      pingTimeoutSec: 2,
      maxHops: 20,
      traceTimeoutSec: 2,
      includeGeo: true,
      httpTimeoutMs: 5_000,
      whoisTimeoutMs: 5_000,
      propagationTimeoutMs: 5_000,
    })
  })

  it('honours overrides', () => {
    const resolved = resolveConfig({ timeoutMs: 1_000, pingCount: 2, includeGeo: false })
    expect(resolved.timeoutMs).toBe(1_000)
    expect(resolved.pingCount).toBe(2)
    expect(resolved.includeGeo).toBe(false)
    expect(resolved.maxHops).toBe(20)
  })
})

describe('buildNetdoctorTools', () => {
  const tools = buildNetdoctorTools(resolveConfig({}))

  it('exposes all eight probes under their canonical names', () => {
    expect(Object.keys(tools).sort()).toEqual(
      ['check_port', 'check_tls', 'dns_lookup', 'dns_propagation', 'my_ip', 'ping_host', 'trace_route', 'whois'].sort(),
    )
  })

  it('gives every tool a name, description, schema and executable', () => {
    for (const [key, definition] of Object.entries(tools)) {
      expect(definition.name).toBe(key)
      expect(definition.description.length).toBeGreaterThan(20)
      expect(definition.parameters).toBeDefined()
      expect(definition.output.schema).toBeDefined()
      expect(typeof definition.execute).toBe('function')
    }
  })

  it('renders a port result as text', () => {
    const block = tools.check_port.output.render(
      { host: 'x', port: 80 },
      { host: 'x', port: 80, status: 'open', connectMs: 1.2 },
    )
    expect(block[0]).toEqual({ type: 'text', text: 'x:80 is open in 1.2 ms' })
  })

  it('renders a ping result as text', () => {
    const block = tools.ping_host.output.render(
      { host: 'x' },
      {
        host: 'x',
        resolvedAddress: '1.2.3.4',
        transmitted: 4,
        received: 4,
        lossPercent: 0,
        rttMs: { min: 1, avg: 2, max: 3 },
      },
    )
    expect(block[0]?.type).toBe('text')
    expect(block[0]?.text).toContain('x (1.2.3.4): 4/4 replies, 0% loss')
    expect(block[0]?.text).toContain('rtt: min 1 ms / avg 2 ms / max 3 ms')
  })

  it('renders a whois summary as text', () => {
    const block = tools.whois.output.render(
      { domain: 'example.com' },
      {
        domain: 'example.com',
        server: 'whois.verisign-grs.com',
        raw: 'fixture',
        rawTruncated: false,
        summary: {
          registrar: 'RESERVED-IANA',
          statuses: ['clientDeleteProhibited'],
          createdDate: '1995-08-14T04:00:00Z',
          expiryDate: '2026-08-13T04:00:00Z',
          nameServers: ['A.IANA-SERVERS.NET'],
        },
      },
    )
    expect(block[0]?.type).toBe('text')
    expect(block[0]?.text).toContain('whois example.com (server: whois.verisign-grs.com):')
    expect(block[0]?.text).toContain('registrar: RESERVED-IANA')
    expect(block[0]?.text).toContain('expiry: 2026-08-13T04:00:00Z')
    expect(block[0]?.text).toContain('nameservers: A.IANA-SERVERS.NET')
  })

  it('renders a whois error result as text', () => {
    const block = tools.whois.output.render(
      { domain: 'example.com' },
      {
        domain: 'example.com',
        server: 'whois.example.net',
        raw: '',
        rawTruncated: false,
        summary: { statuses: [], nameServers: [] },
        error: 'whois query to whois.example.net failed: ETIMEDOUT',
      },
    )
    expect(block[0]?.type).toBe('text')
    expect(block[0]?.text).toContain('whois example.com: whois query to whois.example.net failed: ETIMEDOUT')
  })

  it('renders a propagation result with one group per distinct answer set', () => {
    const block = tools.dns_propagation.output.render(
      { host: 'example.com' },
      {
        host: 'example.com',
        record: 'A',
        resolvers: 3,
        responded: 2,
        failed: 1,
        consistent: false,
        consensus: { fingerprint: 'A {"address":"93.184.216.34"}', resolvers: ['1.1.1.1', '8.8.8.8'] },
        groups: [
          {
            fingerprint: 'A {"address":"93.184.216.34"}',
            resolvers: ['1.1.1.1'],
            answers: [{ name: 'example.com', type: 'A', ttl: 300, data: { address: '93.184.216.34' } }],
          },
          {
            fingerprint: 'A {"address":"93.184.216.99"}',
            resolvers: ['9.9.9.9'],
            answers: [{ name: 'example.com', type: 'A', ttl: 60, data: { address: '93.184.216.99' } }],
          },
        ],
        probes: [
          { label: '1.1.1.1', server: '1.1.1.1', status: 'ok', answers: [], elapsedMs: 12 },
          { label: '9.9.9.9', server: '9.9.9.9', status: 'ok', answers: [], elapsedMs: 30 },
          { label: '8.8.8.8', server: '8.8.8.8', status: 'error', answers: [], elapsedMs: 5_000, error: 'no answer from 8.8.8.8 within 5000 ms', timedOut: true },
        ],
        note: '1 of 3 resolvers did not answer — agreement is partial; resolvers disagree: 2 distinct answer sets',
      },
    )
    const text = block[0]?.text ?? ''
    expect(block[0]?.type).toBe('text')
    expect(text).toContain('dns propagation for example.com A across 3 resolvers: 2 answered, 2 distinct answer set(s)')
    expect(text).toContain('[1/2] 1.1.1.1:')
    expect(text).toContain('93.184.216.99 (ttl 60)')
    expect(text).toContain('⚠️ 8.8.8.8 (8.8.8.8): no answer from 8.8.8.8 within 5000 ms')
  })

  it('renders an empty propagation answer set honestly', () => {
    const block = tools.dns_propagation.output.render(
      { host: 'example.com' },
      {
        host: 'example.com',
        record: 'MX',
        resolvers: 1,
        responded: 1,
        failed: 0,
        consistent: true,
        groups: [{ fingerprint: '', resolvers: ['1.1.1.1'], answers: [] }],
        probes: [{ label: '1.1.1.1', server: '1.1.1.1', status: 'ok', answers: [], elapsedMs: 8 }],
      },
    )
    expect(block[0]?.text).toContain('(no records in the answer)')
  })
})
