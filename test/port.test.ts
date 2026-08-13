/**
 * Tests for the TCP port probe against local listeners (fully offline).
 */

import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { checkPort } from '../src/port.ts'

describe('checkPort', () => {
  let server: ReturnType<typeof createServer>
  let openPort = 0
  let closedPort = 0

  beforeAll(async () => {
    server = createServer((socket) => {
      socket.end()
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    openPort = (server.address() as AddressInfo).port

    const probe = createServer()
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
    closedPort = (probe.address() as AddressInfo).port
    await new Promise<void>((resolve) => probe.close(() => resolve()))
  })

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  it('reports an open port with a connect time', async () => {
    const result = await checkPort('127.0.0.1', openPort, 3_000)
    expect(result.status).toBe('open')
    expect(result.connectMs).toBeTypeOf('number')
  })

  it('reports a closed port (connection refused)', async () => {
    const result = await checkPort('127.0.0.1', closedPort, 3_000)
    expect(result.status).toBe('closed')
    expect(result.detail).toContain('refused')
  })

  it('reports host-lookup failures as unreachable', async () => {
    const result = await checkPort('this-host-does-not-exist-zz.invalid', 80, 3_000)
    expect(result.status).toBe('unreachable')
  })

  it('validates inputs', async () => {
    await expect(checkPort('not a host!!', 80, 3_000)).rejects.toThrow()
    await expect(checkPort('127.0.0.1', 0, 3_000)).rejects.toThrow()
    await expect(checkPort('127.0.0.1', 70000, 3_000)).rejects.toThrow()
    await expect(checkPort('127.0.0.1', 80, 10)).rejects.toThrow()
  })
})
