/**
 * Tests for the TLS probe: a real local TLS server with self-signed fixture
 * certificates (offline), plus the days-remaining helper.
 */

import { readFileSync } from 'node:fs'
import { createServer as createTlsServer, type TlsOptions } from 'node:tls'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { checkTls, computeDaysRemaining } from '../src/tls.ts'

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

describe('computeDaysRemaining', () => {
  it('computes positive days for a future expiry', () => {
    const now = Date.parse('2026-08-14T00:00:00Z')
    expect(computeDaysRemaining('2026-08-24T00:00:00Z', now)).toBe(10)
  })

  it('returns negative values for an already-expired certificate', () => {
    const now = Date.parse('2026-08-14T00:00:00Z')
    expect(computeDaysRemaining('2026-08-04T00:00:00Z', now)).toBe(-10)
  })

  it('returns 0 for unparseable dates', () => {
    expect(computeDaysRemaining('not a date', Date.now())).toBe(0)
  })
})

describe('checkTls', () => {
  let server: ReturnType<typeof createTlsServer>
  let port = 0

  beforeAll(async () => {
    const options: TlsOptions = {
      key: readFileSync(join(fixtures, 'key.pem')),
      cert: readFileSync(join(fixtures, 'cert.pem')),
    }
    server = createTlsServer(options, (socket) => {
      socket.end()
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    port = (server.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  // 回归（R31 门禁接入日实测抓出）：Node ≥20 拒绝把 IP 字面量设为 SNI，
  // 旧实现无条件传 `servername: host` → 对 IP 目标直接抛 ERR_TLS_SNI。
  it('does not set SNI for IP targets (regression: ERR_TLS_SNI on Node ≥20)', async () => {
    const byIp = await checkTls('127.0.0.1', port, 5_000)
    expect(byIp.connected).toBe(true)
    expect(byIp.host).toBe('127.0.0.1')
    const byHostname = await checkTls('localhost', port, 5_000)
    expect(byHostname.connected).toBe(true)
  })

  it('completes a handshake and reports the self-signed certificate', async () => {
    const result = await checkTls('127.0.0.1', port, 5_000)
    expect(result.connected).toBe(true)
    expect(result.protocol).toBeDefined()
    expect(result.cipher).toBeDefined()
    expect(result.cert?.subject).toBe('test.local')
    expect(result.cert?.issuer).toBe('test.local')
    expect(result.cert?.altNames).toContain('DNS:test.local')
    // Days remaining must match the certificate's own validity window
    // (assertion is clock-independent, so the fixture never rots).
    expect(result.cert?.daysRemaining).toBe(computeDaysRemaining(result.cert?.validTo ?? '', Date.now()))
    // self-signed: inspected but never trusted
    expect(result.authorized).toBe(false)
  })

  it('reports connection refused for a closed port', async () => {
    const result = await checkTls('127.0.0.1', 1, 3_000)
    expect(result.connected).toBe(false)
    expect(result.detail).toContain('refused')
  })

  it('validates inputs', async () => {
    await expect(checkTls('bad host!!', 443, 3_000)).rejects.toThrow()
    await expect(checkTls('127.0.0.1', 70000, 3_000)).rejects.toThrow()
  })
})
