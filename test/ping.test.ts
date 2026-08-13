/**
 * Tests for the ping probe: platform argument construction and output parsing.
 * The actual ping binary is not exercised (offline determinism).
 */

import { describe, expect, it } from 'vitest'
import { parseResolvedAddress, pingArgs } from '../src/ping.ts'

describe('pingArgs', () => {
  it('builds windows args (count + per-reply wait in ms)', () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'win32' })
    try {
      expect(pingArgs('example.com', 4, 2)).toEqual(['-n', '4', '-w', '2000', 'example.com'])
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
    }
  })

  it('builds linux/mac-style args (count + per-reply wait in seconds)', () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'linux' })
    try {
      expect(pingArgs('1.1.1.1', 3, 1)).toEqual(['-n', '-c', '3', '-W', '1', '1.1.1.1'])
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
    }
  })

  it('floors the per-reply wait at 1 second', () => {
    const platform = process.platform
    Object.defineProperty(process, 'platform', { value: 'linux' })
    try {
      expect(pingArgs('example.com', 1, 0)).toEqual(['-n', '-c', '1', '-W', '1', 'example.com'])
    } finally {
      Object.defineProperty(process, 'platform', { value: platform })
    }
  })
})

describe('parseResolvedAddress', () => {
  it('extracts the address from the banner', () => {
    expect(parseResolvedAddress('PING example.com (93.184.216.34) 56(84) bytes of data.')).toBe('93.184.216.34')
  })

  it('handles IPv6 banners', () => {
    expect(parseResolvedAddress('PING6 ::1(::1) 56 data bytes')).toBe('::1')
  })

  it('returns undefined without a banner', () => {
    expect(parseResolvedAddress('64 bytes from 1.1.1.1: icmp_seq=1 ttl=57')).toBeUndefined()
  })
})
