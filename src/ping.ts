/**
 * ICMP ping probe: delegates to the platform's ping utility (fixed argument
 * arrays, never a shell) and parses the human-readable summary.
 *
 * @module dsh-netdoctor/ping
 */

import { assertValidTarget, parsePacketSummary, parseRttSummary, round2, runProcess } from './util.ts'

export type PingResult = {
  host: string
  resolvedAddress: string | undefined
  transmitted: number
  received: number
  lossPercent: number
  rttMs: { min: number; avg: number; max: number } | undefined
  note: string | undefined
  raw: string
}

/** Build the platform-specific argument array for the ping binary. */
export function pingArgs(host: string, count: number, timeoutSec: number): string[] {
  const countArg = String(count)
  if (process.platform === 'win32') {
    const waitMs = String(Math.max(timeoutSec, 1) * 1000)
    return ['-n', countArg, '-w', waitMs, host]
  }
  if (process.platform === 'darwin') {
    const waitSec = String(Math.max(timeoutSec, 1))
    return ['-n', '-c', countArg, '-W', waitSec, host]
  }
  const waitSec = String(Math.max(timeoutSec, 1))
  return ['-n', '-c', countArg, '-W', waitSec, host]
}

/** Parse the resolved address from a "PING host (1.2.3.4) ..." banner line. */
export function parseResolvedAddress(text: string): string | undefined {
  const match = /PING\d*\s+\S+?\s*\(([^)]+)\)/.exec(text)
  if (match === null) return undefined
  const address = match[1]
  return address === undefined ? undefined : address
}

/** Total time budget for a ping run: generous enough for `count` replies plus setup. */
function pingTimeoutMs(count: number, timeoutSec: number): number {
  return Math.max(timeoutSec * 1000 * (count + 2), 10_000)
}

/** Ping a host `count` times and summarize the result. */
export async function pingHost(hostInput: string, count: number, timeoutSec: number): Promise<PingResult> {
  const host = assertValidTarget(hostInput)
  if (!Number.isInteger(count) || count < 1 || count > 20) {
    throw new Error('count must be an integer between 1 and 20')
  }
  if (typeof timeoutSec !== 'number' || timeoutSec < 1 || timeoutSec > 60) {
    throw new Error('timeoutSec must be a number between 1 and 60')
  }

  const result = await runProcess('ping', pingArgs(host, count, timeoutSec), pingTimeoutMs(count, timeoutSec))
  if (result.spawnError !== undefined) {
    throw new Error(`ping failed: ${result.spawnError}`)
  }

  const raw = result.stdout.trim() === '' ? result.stderr : result.stdout
  const summary = parsePacketSummary(raw)
  if (summary === undefined) {
    if (result.timedOut) {
      return {
        host,
        resolvedAddress: parseResolvedAddress(raw),
        transmitted: count,
        received: 0,
        lossPercent: 100,
        rttMs: undefined,
        note: `no ping summary parsed; the probe was killed after ${pingTimeoutMs(count, timeoutSec)} ms (all replies may have been dropped)`,
        raw: raw.slice(0, 4000),
      }
    }
    throw new Error(`ping produced no usable output (exit code ${String(result.code)}): ${raw.slice(0, 500) || '(empty output)'}`)
  }

  const rtt = parseRttSummary(raw)
  let note: string | undefined
  if (result.timedOut) {
    note = 'probe hit its time budget; results below are partial'
  }
  return {
    host,
    resolvedAddress: parseResolvedAddress(raw),
    transmitted: summary.transmitted,
    received: summary.received,
    lossPercent: round2(summary.lossPercent),
    rttMs: rtt === undefined ? undefined : { min: round2(rtt.min), avg: round2(rtt.avg), max: round2(rtt.max) },
    note,
    raw: raw.slice(0, 4000),
  }
}
