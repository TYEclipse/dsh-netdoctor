/**
 * Tests for DNS lookup logic with a mocked node:dns/promises (fully offline,
 * deterministic record-type dispatch).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { dnsLookup } from '../src/dns.ts'

const mocks = vi.hoisted(() => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  resolveCname: vi.fn(),
  resolveMx: vi.fn(),
  resolveTxt: vi.fn(),
  resolveNs: vi.fn(),
  resolveSrv: vi.fn(),
  reverse: vi.fn(),
  setServers: vi.fn(),
}))

vi.mock('node:dns/promises', () => {
  class FakeResolver {
    resolve4 = mocks.resolve4
    resolve6 = mocks.resolve6
    resolveCname = mocks.resolveCname
    resolveMx = mocks.resolveMx
    resolveTxt = mocks.resolveTxt
    resolveNs = mocks.resolveNs
    resolveSrv = mocks.resolveSrv
    reverse = mocks.reverse
    setServers = mocks.setServers
  }
  return { default: FakeResolver, Resolver: FakeResolver }
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('dnsLookup', () => {
  it('dispatches A records', async () => {
    mocks.resolve4.mockResolvedValue([
      { address: '93.184.216.34', ttl: 300 },
      { address: '93.184.216.35', ttl: 300 },
    ])
    const result = await dnsLookup('example.com', 'A', undefined)
    expect(result.server).toBe('system')
    expect(result.answers).toHaveLength(2)
    expect(result.answers[0]).toEqual({ name: 'example.com', type: 'A', ttl: 300, data: { address: '93.184.216.34' } })
    expect(mocks.resolve4).toHaveBeenCalledWith('example.com', { ttl: true })
  })

  it('dispatches MX records with priority', async () => {
    mocks.resolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])
    const result = await dnsLookup('example.com', 'MX', undefined)
    expect(result.answers[0]?.data).toEqual({ exchange: 'mail.example.com', priority: 10 })
  })

  it('dispatches TXT records', async () => {
    mocks.resolveTxt.mockResolvedValue([['v=spf1 -all']])
    const result = await dnsLookup('example.com', 'TXT', undefined)
    expect(result.answers[0]?.data).toEqual({ entries: ['v=spf1 -all'] })
  })

  it('dispatches SRV records', async () => {
    mocks.resolveSrv.mockResolvedValue([{ name: 'sip.example.com', port: 5060, priority: 0, weight: 5 }])
    const result = await dnsLookup('_sip._tcp.example.com', 'SRV', undefined)
    expect(result.answers[0]?.data).toEqual({ port: 5060, priority: 0, weight: 5, target: 'sip.example.com' })
  })

  it('dispatches PTR records via reverse()', async () => {
    mocks.reverse.mockResolvedValue(['localhost'])
    const result = await dnsLookup('127.0.0.1', 'PTR', undefined)
    expect(mocks.reverse).toHaveBeenCalledWith('127.0.0.1')
    expect(result.answers[0]?.data).toEqual({ target: 'localhost' })
  })

  it('uses a custom nameserver when provided', async () => {
    mocks.resolve4.mockResolvedValue([{ address: '1.2.3.4', ttl: 60 }])
    const result = await dnsLookup('example.com', 'A', '8.8.8.8')
    expect(mocks.setServers).toHaveBeenCalledWith(['8.8.8.8'])
    expect(result.server).toBe('8.8.8.8')
  })

  it('validates targets', async () => {
    await expect(dnsLookup('bad host;', 'A', undefined)).rejects.toThrow()
  })
})
