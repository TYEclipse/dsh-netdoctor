/**
 * TCP port probe: attempts a raw TCP connect and classifies the outcome as
 * open / closed / filtered. Uses node:net — no external binaries.
 *
 * @module dsh-netdoctor/port
 */

import { createConnection } from 'node:net'
import { assertValidPort, assertValidTarget, round2 } from './util.ts'

export type PortStatus = 'open' | 'closed' | 'filtered' | 'unreachable'

export type PortResult = {
  host: string
  port: number
  status: PortStatus
  connectMs: number | undefined
  detail: string | undefined
}

/** Try to open a TCP connection; classify the outcome. */
export async function checkPort(hostInput: string, portInput: number, timeoutMs: number): Promise<PortResult> {
  const host = assertValidTarget(hostInput)
  const port = assertValidPort(portInput)
  if (typeof timeoutMs !== 'number' || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new Error('timeoutMs must be a number between 100 and 60000')
  }

  return new Promise((resolve) => {
    const startedAt = Date.now()
    const socket = createConnection({ host, port })
    let settled = false

    const finish = (status: PortStatus, detail?: string): void => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve({
        host,
        port,
        status,
        connectMs: status === 'open' ? round2(Date.now() - startedAt) : undefined,
        detail,
      })
    }

    socket.setTimeout(timeoutMs, () => finish('filtered', `no response within ${timeoutMs} ms (firewall or unreachable host)`))
    socket.once('connect', () => finish('open'))
    socket.once('error', (error: NodeJS.ErrnoException) => {
      const code = error.code ?? ''
      if (code === 'ECONNREFUSED') {
        finish('closed', 'connection refused (nothing is listening, or the host rejects the port)')
      } else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
        finish('unreachable', error.message)
      } else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
        finish('unreachable', `host lookup failed: ${error.message}`)
      } else {
        finish('filtered', error.message)
      }
    })
  })
}
