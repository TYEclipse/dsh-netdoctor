/**
 * Unit tests for shared helpers: target/port validation, ping/traceroute
 * output parsers, and process execution.
 */

import { describe, expect, it } from 'vitest'
import {
  assertValidPort,
  assertValidTarget,
  parsePacketSummary,
  parseRttSummary,
  runProcess,
} from '../src/util.ts'

describe('assertValidTarget', () => {
  it('accepts hostnames, IPv4 and IPv6 literals', () => {
    expect(assertValidTarget('example.com')).toBe('example.com')
    expect(assertValidTarget('sub.domain.example.co.uk')).toBe('sub.domain.example.co.uk')
    expect(assertValidTarget('localhost')).toBe('localhost')
    expect(assertValidTarget('127.0.0.1')).toBe('127.0.0.1')
    expect(assertValidTarget('8.8.8.8')).toBe('8.8.8.8')
    expect(assertValidTarget('::1')).toBe('::1')
    expect(assertValidTarget('2001:db8::1')).toBe('2001:db8::1')
  })

  it('rejects garbage, shell metacharacters and whitespace', () => {
    expect(() => assertValidTarget('')).toThrow()
    expect(() => assertValidTarget('a b')).toThrow()
    expect(() => assertValidTarget('x; rm -rf /')).toThrow()
    expect(() => assertValidTarget('$(whoami)')).toThrow()
    expect(() => assertValidTarget('example.com/path')).toThrow()
    expect(() => assertValidTarget('256.1.1.1')).toThrow()
    expect(() => assertValidTarget('1.2.3.256')).toThrow()
    expect(() => assertValidTarget('-bad.example')).toThrow()
  })

  it('trims surrounding whitespace', () => {
    expect(assertValidTarget('  example.com  ')).toBe('example.com')
  })
})

describe('assertValidPort', () => {
  it('accepts ports 1–65535', () => {
    expect(assertValidPort(1)).toBe(1)
    expect(assertValidPort(443)).toBe(443)
    expect(assertValidPort(65535)).toBe(65535)
  })

  it('rejects everything else', () => {
    expect(() => assertValidPort(0)).toThrow()
    expect(() => assertValidPort(65536)).toThrow()
    expect(() => assertValidPort(80.5)).toThrow()
    expect(() => assertValidPort('80')).toThrow()
    expect(() => assertValidPort(NaN)).toThrow()
    expect(() => assertValidPort(undefined)).toThrow()
  })
})

describe('parseRttSummary', () => {
  it('parses unix min/avg/max figures', () => {
    expect(parseRttSummary('rtt min/avg/max/mdev = 1.234/2.345/3.456/0.5 ms')).toEqual({
      min: 1.234,
      avg: 2.345,
      max: 3.456,
    })
  })

  it('returns undefined for unrelated lines', () => {
    expect(parseRttSummary('64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms')).toBeUndefined()
  })
})

describe('parsePacketSummary', () => {
  it('parses the linux/mac summary form', () => {
    expect(parsePacketSummary('4 packets transmitted, 3 received, 25% packet loss, time 3004ms')).toEqual({
      transmitted: 4,
      received: 3,
      lossPercent: 25,
    })
  })

  it('parses the windows summary form', () => {
    expect(parsePacketSummary('    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),')).toEqual({
      transmitted: 4,
      received: 4,
      lossPercent: 0,
    })
  })

  it('returns undefined without a summary', () => {
    expect(parsePacketSummary('PING example.com (93.184.216.34) 56(84) bytes of data.')).toBeUndefined()
  })
})

describe('runProcess', () => {
  it('captures stdout and exit code', async () => {
    const result = await runProcess('node', ['-e', 'console.log("hello from probe")'], 5_000)
    expect(result.spawnError).toBeUndefined()
    expect(result.code).toBe(0)
    expect(result.stdout).toContain('hello from probe')
    expect(result.timedOut).toBe(false)
  })

  it('reports a missing binary via spawnError', async () => {
    const result = await runProcess('definitely-not-a-real-binary-xyz', [], 5_000)
    expect(result.spawnError).toContain('not installed')
    expect(result.code).toBeNull()
  })

  it('enforces the timeout', async () => {
    const result = await runProcess('node', ['-e', 'setTimeout(() => console.log("late"), 3000)'], 300)
    expect(result.timedOut).toBe(true)
    expect(result.stdout).not.toContain('late')
  })
})
