/**
 * Traceroute probe: delegates to the platform's traceroute utility (tracert on
 * Windows) and parses the hop list. Parsing is lenient — unparseable lines are
 * kept verbatim so the output is always useful.
 *
 * @module dsh-netdoctor/route
 */

import { assertValidTarget, runProcess } from './util.ts'

export type TraceHop = {
  hop: number
  host: string | undefined
  address: string | undefined
  rttsMs: number[]
  raw: string
}

export type TraceResult = {
  host: string
  maxHops: number
  hops: TraceHop[]
  complete: boolean
  note: string | undefined
  raw: string
}

/** Build the platform-specific argument array for the traceroute binary. */
export function traceArgs(host: string, maxHops: number, perHopTimeoutSec: number): { binary: string; args: string[] } {
  const maxHopsArg = String(maxHops)
  if (process.platform === 'win32') {
    return { binary: 'tracert', args: ['-d', '-h', maxHopsArg, '-w', String(perHopTimeoutSec * 1000), host] }
  }
  return {
    binary: 'traceroute',
    args: ['-m', maxHopsArg, '-q', '1', '-w', String(perHopTimeoutSec), host],
  }
}

/** Parse one traceroute output line into a hop (returns undefined for banners/headers). */
export function parseTraceLine(line: string): TraceHop | undefined {
  const trimmed = line.trim()
  if (trimmed === '') return undefined
  const match = /^\s*(\d{1,2})\s+(.+)$/.exec(trimmed)
  if (match === null) return undefined
  const hop = Number(match[1])
  const rest = match[2] ?? ''
  if (!Number.isInteger(hop) || hop < 1) return undefined

  // Windows form: " 1     2 ms     1 ms     1 ms  192.168.1.1"
  const winMatch = /^((?:\d+\s*ms|\*)\s*){1,3}(\S+)$/i.exec(rest)
  if (winMatch !== null) {
    const target = winMatch[2] ?? ''
    const rtts = [...rest.matchAll(/(\d+)\s*ms/gi)].map((m) => Number(m[1]))
    return {
      hop,
      host: undefined,
      address: /^[\d.]+$/.test(target) || target.includes(':') ? target : undefined,
      rttsMs: rtts,
      raw: trimmed,
    }
  }

  // Unix form: " 3  router.example.com (10.0.0.1)  12.345 ms" or " 4  * * *"
  const rtts = [...rest.matchAll(/([\d.]+)\s*ms/g)].map((m) => Number(m[1]))
  const hostMatch = /^(\S+?)\s+\(([^)]+)\)/.exec(rest)
  if (hostMatch !== null) {
    return { hop, host: hostMatch[1], address: hostMatch[2], rttsMs: rtts, raw: trimmed }
  }
  if (/^\s*\*\s*(\*\s*)*$/.test(rest)) {
    return { hop, host: undefined, address: undefined, rttsMs: [], raw: trimmed }
  }
  const bare = rest.split(/\s+/)[0]
  if (bare !== undefined && bare !== '*' && rtts.length > 0) {
    return { hop, host: bare, address: /^[\d.]+$/.test(bare) ? bare : undefined, rttsMs: rtts, raw: trimmed }
  }
  return undefined
}

/** Run a traceroute and parse the hop list. */
export async function traceRoute(hostInput: string, maxHops: number, perHopTimeoutSec: number): Promise<TraceResult> {
  const host = assertValidTarget(hostInput)
  if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 64) {
    throw new Error('maxHops must be an integer between 1 and 64')
  }
  if (typeof perHopTimeoutSec !== 'number' || perHopTimeoutSec < 1 || perHopTimeoutSec > 30) {
    throw new Error('perHopTimeoutSec must be a number between 1 and 30')
  }

  const { binary, args } = traceArgs(host, maxHops, perHopTimeoutSec)
  const timeoutMs = Math.max(perHopTimeoutSec * 1000 * (maxHops + 4), 30_000)
  const result = await runProcess(binary, args, timeoutMs)

  if (result.spawnError !== undefined) {
    throw new Error(
      process.platform === 'darwin' && result.spawnError.includes('not installed')
        ? `traceroute is not installed on macOS by default — install it with "brew install traceroute"`
        : `traceroute failed: ${result.spawnError}`,
    )
  }

  const raw = (result.stdout + result.stderr).trim()
  const hops: TraceHop[] = []
  for (const line of raw.split('\n')) {
    const parsed = parseTraceLine(line)
    if (parsed !== undefined) hops.push(parsed)
  }
  if (hops.length === 0) {
    throw new Error(`traceroute produced no usable output (exit code ${String(result.code)}): ${raw.slice(0, 500) || '(empty output)'}`)
  }

  const last = hops[hops.length - 1]
  const reachedTarget = last !== undefined && (last.host === host || last.address === host || (last.rttsMs.length > 0 && last.hop < maxHops))
  return {
    host,
    maxHops,
    hops,
    complete: reachedTarget,
    note: result.timedOut ? 'probe hit its time budget; the hop list may be incomplete' : undefined,
    raw: raw.slice(0, 4000),
  }
}
