/**
 * Tests for traceroute parsing (unix + windows forms, timeouts, banners).
 */

import { describe, expect, it } from 'vitest'
import { parseTraceLine, traceArgs } from '../src/route.ts'

describe('parseTraceLine', () => {
  it('parses a unix hop with host and address', () => {
    const hop = parseTraceLine(' 3  router.example.com (10.0.0.1)  12.345 ms')
    expect(hop).toEqual({
      hop: 3,
      host: 'router.example.com',
      address: '10.0.0.1',
      rttsMs: [12.345],
      raw: '3  router.example.com (10.0.0.1)  12.345 ms',
    })
  })

  it('parses a unix hop with multiple probes', () => {
    const hop = parseTraceLine(' 2  192.168.1.1 (192.168.1.1)  1.234 ms  1.5 ms  1.6 ms')
    expect(hop?.rttsMs).toEqual([1.234, 1.5, 1.6])
    expect(hop?.address).toBe('192.168.1.1')
  })

  it('parses a no-reply hop', () => {
    const hop = parseTraceLine(' 4  * * *')
    expect(hop).toEqual({ hop: 4, host: undefined, address: undefined, rttsMs: [], raw: '4  * * *' })
  })

  it('parses a windows hop', () => {
    const hop = parseTraceLine('  3    12 ms    11 ms    12 ms  203.0.113.7')
    expect(hop?.hop).toBe(3)
    expect(hop?.address).toBe('203.0.113.7')
    expect(hop?.rttsMs).toEqual([12, 11, 12])
  })

  it('ignores banners and headers', () => {
    expect(parseTraceLine('traceroute to example.com (93.184.216.34), 30 hops max')).toBeUndefined()
    expect(parseTraceLine('Tracing route to example.com [93.184.216.34]')).toBeUndefined()
    expect(parseTraceLine('')).toBeUndefined()
  })

  it('ignores a windows timeout hop without an address', () => {
    expect(parseTraceLine('  4     *        *        *     Request timed out.')).toBeUndefined()
  })
})

describe('traceArgs', () => {
  it('builds unix traceroute args', () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'linux' })
    try {
      expect(traceArgs('example.com', 20, 2)).toEqual({
        binary: 'traceroute',
        args: ['-m', '20', '-q', '1', '-w', '2', 'example.com'],
      })
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
    }
  })

  it('builds windows tracert args', () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'win32' })
    try {
      expect(traceArgs('example.com', 10, 2)).toEqual({
        binary: 'tracert',
        args: ['-d', '-h', '10', '-w', '2000', 'example.com'],
      })
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
    }
  })
})
