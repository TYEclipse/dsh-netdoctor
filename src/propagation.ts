/**
 * DNS propagation probe: query the same record through several resolvers in
 * parallel and report where the answers agree and where they differ. Answers
 * from each resolver are grouped by a canonical fingerprint, so "4 of 6 agree"
 * is counted from the actual record data — never assumed.
 *
 * @module dsh-netdoctor/propagation
 */

import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { dnsLookup, type DnsAnswer, type DnsRecordType, type DnsResult } from './dns.ts'
import { assertValidResolver, assertValidTarget, round2 } from './util.ts'

/** One resolver to probe. */
export interface PropagationResolver {
  label: string
  server: string
}

/**
 * Public resolvers used when the caller does not name its own. Kept as a fixed
 * list (not discovered) so a propagation check is reproducible.
 */
export const DEFAULT_RESOLVERS: readonly PropagationResolver[] = [
  { label: 'Google', server: '8.8.8.8' },
  { label: 'Cloudflare', server: '1.1.1.1' },
  { label: 'Quad9', server: '9.9.9.9' },
  { label: 'OpenDNS', server: '208.67.222.222' },
  { label: 'Level3', server: '4.2.2.1' },
  { label: 'DNS.SB', server: '185.222.222.222' },
]

/** One resolver's outcome. */
export type PropagationProbe = {
  label: string
  server: string
  status: 'ok' | 'error'
  answers: DnsAnswer[]
  elapsedMs: number
  error?: string
  timedOut?: boolean
}

/** All resolvers that returned the same answer set, grouped together. */
export type PropagationGroup = {
  fingerprint: string
  resolvers: string[]
  answers: DnsAnswer[]
}

/** Result of a propagation check. */
export type PropagationResult = {
  host: string
  record: DnsRecordType
  resolvers: number
  responded: number
  failed: number
  /** Every resolver that answered returned the same records. */
  consistent: boolean
  /** The answer set reported by the most resolvers (omitted when no set has ≥2 reporters). */
  consensus?: { fingerprint: string; resolvers: string[] }
  /** One entry per distinct answer set, most-reported first. */
  groups: PropagationGroup[]
  probes: PropagationProbe[]
  note?: string
}

/** Lookup function (injectable for tests); same shape as `dnsLookup`. */
export type PropagationLookup = (
  host: string,
  record: DnsRecordType,
  server: string | undefined,
) => Promise<DnsResult>

export interface PropagationOptions {
  /** Custom resolver IPs to probe instead of the built-in public set (at most 10). */
  resolvers?: string[]
  /** Per-resolver answer deadline in ms (100–60000, default 5000). */
  timeoutMs?: number
  /** Lookup implementation override (tests). */
  lookup?: PropagationLookup
}

/** Deterministic serialization of a JSON value with sorted object keys. */
function stableValue(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(stableValue).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${key}=${stableValue(value[key] ?? null)}`)
    return `{${entries.join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

/**
 * Canonical fingerprint of an answer set: record type + record data, one line
 * per record, sorted. Order of the answers (and the key order inside each
 * record) therefore cannot change the fingerprint — resolver answer order is
 * not meaningful, and an unstable fingerprint would report false disagreement.
 */
export function answerFingerprint(answers: DnsAnswer[]): string {
  return answers
    .map((answer) => `${answer.type} ${stableValue(answer.data)}`)
    .sort()
    .join('\n')
}

async function probeOnce(
  resolver: PropagationResolver,
  host: string,
  record: DnsRecordType,
  timeoutMs: number,
  lookup: PropagationLookup,
): Promise<PropagationProbe> {
  const startedAt = Date.now()
  let timedOut = false
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true
      reject(new Error(`no answer from ${resolver.server} within ${timeoutMs} ms`))
    }, timeoutMs)
  })

  try {
    const result = await Promise.race([lookup(host, record, resolver.server), deadline])
    return {
      label: resolver.label,
      server: resolver.server,
      status: 'ok',
      answers: result.answers,
      elapsedMs: round2(Date.now() - startedAt),
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return timedOut
      ? {
        label: resolver.label,
        server: resolver.server,
        status: 'error',
        answers: [],
        elapsedMs: round2(Date.now() - startedAt),
        error: message,
        timedOut: true,
      }
      : {
        label: resolver.label,
        server: resolver.server,
        status: 'error',
        answers: [],
        elapsedMs: round2(Date.now() - startedAt),
        error: message,
      }
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

/**
 * Query one record type through several resolvers and report agreement.
 *
 * A failed or slow resolver is reported as failed — never folded into the
 * majority. `consistent` therefore means "every resolver that answered agreed",
 * and `note` says out loud when the evidence is partial.
 */
export async function dnsPropagation(
  hostInput: string,
  record: DnsRecordType,
  options: PropagationOptions = {},
): Promise<PropagationResult> {
  const host = assertValidTarget(hostInput)
  const timeoutMs = options.timeoutMs ?? 5_000
  if (typeof timeoutMs !== 'number' || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new Error('timeoutMs must be a number between 100 and 60000')
  }

  const custom = options.resolvers
  let resolvers: PropagationResolver[]
  if (custom !== undefined && custom.length > 0) {
    if (custom.length > 10) {
      throw new Error(`at most 10 resolvers per propagation check (got ${custom.length})`)
    }
    resolvers = custom.map((server) => {
      const valid = assertValidResolver(server)
      return { label: valid, server: valid }
    })
  } else {
    resolvers = [...DEFAULT_RESOLVERS]
  }

  const lookup = options.lookup ?? dnsLookup
  const probes = await Promise.all(
    resolvers.map((resolver) => probeOnce(resolver, host, record, timeoutMs, lookup)),
  )

  const answered = probes.filter((probe) => probe.status === 'ok')
  const groups: PropagationGroup[] = []
  for (const probe of answered) {
    const fingerprint = answerFingerprint(probe.answers)
    let group = groups.find((candidate) => candidate.fingerprint === fingerprint)
    if (group === undefined) {
      group = { fingerprint, resolvers: [], answers: probe.answers }
      groups.push(group)
    }
    group.resolvers.push(probe.label)
  }
  // Most-reported answer set first; equal sizes keep resolver order (stable sort).
  groups.sort((a, b) => b.resolvers.length - a.resolvers.length)

  const failed = probes.length - answered.length
  const notes: string[] = []
  if (answered.length === 0) {
    notes.push(`no resolver answered (${probes.length} probed)`)
  } else if (failed > 0) {
    notes.push(`${failed} of ${probes.length} resolvers did not answer — agreement is partial`)
  }
  if (groups.length > 1) {
    notes.push(`resolvers disagree: ${groups.length} distinct answer sets`)
  }

  const top = groups[0]
  const result: PropagationResult = {
    host,
    record,
    resolvers: probes.length,
    responded: answered.length,
    failed,
    consistent: answered.length > 0 && groups.length === 1,
    groups,
    probes,
  }
  if (top !== undefined && top.resolvers.length >= 2) {
    result.consensus = { fingerprint: top.fingerprint, resolvers: top.resolvers }
  }
  if (notes.length > 0) result.note = notes.join('; ')
  return result
}
