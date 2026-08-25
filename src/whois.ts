/**
 * WHOIS lookup over the classic TCP port 43 protocol — no external services
 * beyond the registry servers themselves, zero runtime dependencies
 * (node:net raw socket only).
 *
 * Server discovery follows the standard IANA referral chain: query
 * whois.iana.org first, read the `refer:` line it returns, then re-query the
 * referred registry server. An explicit server can be supplied to skip
 * discovery. The raw WHOIS text is returned alongside a best-effort
 * structured summary (registrar, statuses, dates, nameservers).
 *
 * @module dsh-netdoctor/whois
 */

import * as net from 'node:net'
import { assertValidTarget } from './util.ts'

/** Default WHOIS discovery endpoint (IANA). */
export const IANA_SERVER = 'whois.iana.org'

/** Cap on the raw WHOIS text returned to the caller (context budget). */
export const RAW_CAP = 12_000

/**
 * Best-effort fallback WHOIS servers for common TLDs. IANA discovery is
 * consulted first, but its referral line is not always present (or the
 * server may be unreachable), so well-known registries are used directly
 * as a second path. Servers listed here accept a bare domain query.
 */
const TLD_WHOIS: Record<string, string> = {
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  edu: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  info: 'whois.afilias.net',
  biz: 'whois.nic.biz',
  mobi: 'whois.nic.mobi',
  io: 'whois.nic.io',
  ai: 'whois.nic.ai',
  co: 'whois.nic.co',
  me: 'whois.nic.me',
  xyz: 'whois.nic.xyz',
  app: 'whois.nic.google',
  dev: 'whois.nic.google',
  page: 'whois.nic.google',
  cn: 'whois.cnnic.cn',
  uk: 'whois.nic.uk',
  us: 'whois.nic.us',
  ca: 'whois.cira.ca',
}

/** Extract the last label (TLD) of a hostname, lowercased. */
export function tldOf(host: string): string {
  const dot = host.lastIndexOf('.')
  return dot === -1 ? host.toLowerCase() : host.slice(dot + 1).toLowerCase()
}

/**
 * Fallback WHOIS server for a host: ARIN for IP literals (the conventional
 * default RIR; non-ARIN ranges answer with a ReferralServer line in the raw
 * text), otherwise the TLD map.
 */
export function fallbackWhoisServer(host: string): string | undefined {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) return 'whois.arin.net'
  return TLD_WHOIS[tldOf(host)]
}

/** Best-effort structured summary of a WHOIS response. */
export interface WhoisSummary {
  registrar?: string
  statuses: string[]
  createdDate?: string
  updatedDate?: string
  expiryDate?: string
  nameServers: string[]
}

/** Full result of a WHOIS lookup. */
export interface WhoisResult {
  domain: string
  /** Registry server that produced the answer. */
  server: string
  /** Raw WHOIS text (capped at {@link RAW_CAP}). */
  raw: string
  rawTruncated: boolean
  summary: WhoisSummary
  /** Set when the lookup failed; raw/summary are then empty. */
  error?: string
}

/**
 * Open a raw TCP connection to a WHOIS server on port 43 (configurable for
 * tests), send the query line, and collect the full response.
 * Resolves with the response text; rejects with a descriptive error on
 * connection failure or timeout before any data arrives.
 */
export function rawWhoisQuery(server: string, query: string, timeoutMs: number, port = 43): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = ''
    let settled = false
    let socket: net.Socket | undefined
    try {
      socket = net.connect({ host: server, port })
    } catch (error) {
      reject(new Error(`cannot connect to ${server}:${port}: ${error instanceof Error ? error.message : String(error)}`))
      return
    }

    const finish = (): void => {
      if (settled) return
      settled = true
      socket?.destroy()
      resolve(buffer)
    }

    socket.setTimeout(timeoutMs)
    socket.on('connect', () => {
      socket?.write(`${query}\r\n`)
    })
    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8')
    })
    socket.on('end', () => {
      finish()
    })
    socket.on('close', () => {
      if (settled) return
      // Servers that close without ending: keep partial data if any.
      if (buffer.length > 0) {
        finish()
        return
      }
      settled = true
      reject(new Error(`whois server ${server} closed the connection without a response`))
    })
    socket.on('timeout', () => {
      if (buffer.length > 0) {
        finish()
        return
      }
      settled = true
      socket.destroy()
      reject(new Error(`whois query to ${server} timed out after ${timeoutMs} ms`))
    })
    socket.on('error', (error: NodeJS.ErrnoException) => {
      if (settled) return
      settled = true
      reject(new Error(`whois query to ${server} failed: ${error.code ?? error.message}`))
    })
  })
}

/** Extract the `refer:` server from an IANA WHOIS response, if present. */
export function parseIanaReferral(text: string): string | undefined {
  const match = /^\s*refer:\s*(\S+)/im.exec(text)
  if (match === null) return undefined
  const server = (match[1] ?? '').trim().toLowerCase()
  return server === '' ? undefined : server
}

/** Best-effort extraction of the structured fields agents care about. */
export function parseWhoisSummary(text: string): WhoisSummary {
  const summary: WhoisSummary = { statuses: [], nameServers: [] }

  const firstOf = (patterns: RegExp[]): string | undefined => {
    for (const pattern of patterns) {
      const match = pattern.exec(text)
      if (match !== null) {
        const value = (match[1] ?? '').trim()
        if (value !== '') return value
      }
    }
    return undefined
  }

  const registrar = firstOf([/^\s*registrar:\s*(.+)$/im])
  if (registrar !== undefined) summary.registrar = registrar

  const createdDate = firstOf([/^\s*creation\s+date:\s*(.+)$/im, /^\s*created(?:\s+on)?:\s*(.+)$/im, /^\s*registered\s+on:\s*(.+)$/im])
  if (createdDate !== undefined) summary.createdDate = createdDate

  const updatedDate = firstOf([/^\s*updated\s+date:\s*(.+)$/im, /^\s*last\s+updated(?:\s+on)?:\s*(.+)$/im])
  if (updatedDate !== undefined) summary.updatedDate = updatedDate

  const expiryDate = firstOf([/^\s*registry\s+expiry\s+date:\s*(.+)$/im, /^\s*expiration\s+date:\s*(.+)$/im, /^\s*expiry\s+date:\s*(.+)$/im, /^\s*paid-till:\s*(.+)$/im])
  if (expiryDate !== undefined) summary.expiryDate = expiryDate

  for (const pattern of [/^\s*status:\s*(.+)$/img, /^\s*domain\s+status:\s*(.+)$/img]) {
    for (const match of text.matchAll(pattern)) {
      const value = (match[1] ?? '').trim()
      if (value !== '' && !summary.statuses.includes(value)) summary.statuses.push(value)
    }
  }

  const seen = new Set<string>()
  for (const pattern of [/^\s*name\s+server:\s*(.+)$/img, /^\s*nserver:\s*(.+)$/img]) {
    for (const match of text.matchAll(pattern)) {
      const value = (match[1] ?? '').trim()
      const key = value.toLowerCase()
      if (value !== '' && !seen.has(key)) {
        seen.add(key)
        summary.nameServers.push(value)
      }
    }
  }

  return summary
}

/**
 * Perform a WHOIS lookup for a domain or IP address. With an explicit
 * `server` the query goes straight there; otherwise whois.iana.org is
 * consulted first and its `refer:` line is followed to the registry server.
 * If discovery is unreachable or returns no referral, a best-effort fallback
 * server is tried (TLD map, ARIN for IP literals). Failures are reported in
 * `error` rather than thrown, so the tool always returns a structured result.
 */
export async function whoisLookup(domainInput: string, server: string | undefined, timeoutMs: number): Promise<WhoisResult> {
  const domain = assertValidTarget(domainInput, 'domain')
  const explicit = server !== undefined && server.trim() !== '' ? server.trim() : undefined

  const build = (used: string, raw: string, error?: string): WhoisResult => {
    const rawTruncated = raw.length > RAW_CAP
    // NB: `error` is only attached when present — a live `error: undefined`
    // key fails the dsh-tools lossless-JSON output gate (R7 discipline).
    const result: WhoisResult = {
      domain,
      server: used,
      raw: rawTruncated ? raw.slice(0, RAW_CAP) : raw,
      rawTruncated,
      summary: parseWhoisSummary(raw),
    }
    if (error !== undefined) result.error = error
    return result
  }

  if (explicit !== undefined) {
    try {
      return build(explicit, await rawWhoisQuery(explicit, domain, timeoutMs))
    } catch (error) {
      return build(explicit, '', error instanceof Error ? error.message : String(error))
    }
  }

  // Step 1 — IANA discovery (best effort; an unreachable IANA server must
  // not block the lookup when a fallback registry is known).
  let ianaText: string | undefined
  try {
    ianaText = await rawWhoisQuery(IANA_SERVER, domain, timeoutMs)
  } catch {
    ianaText = undefined
  }

  if (ianaText !== undefined) {
    const referral = parseIanaReferral(ianaText)
    if (referral !== undefined) {
      try {
        return build(referral, await rawWhoisQuery(referral, domain, timeoutMs))
      } catch (error) {
        return build(referral, '', `referral server ${referral} failed: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
  }

  // Step 2 — fallback registry for common TLDs and IP literals.
  const fallback = fallbackWhoisServer(domain)
  if (fallback !== undefined) {
    try {
      return build(fallback, await rawWhoisQuery(fallback, domain, timeoutMs))
    } catch (error) {
      return build(fallback, '', `fallback server ${fallback} failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // Step 3 — no referral and no fallback: the IANA answer (if any) is the answer.
  if (ianaText !== undefined) {
    return build(IANA_SERVER, ianaText)
  }
  return build(IANA_SERVER, '', `IANA discovery failed and no fallback WHOIS server is known for ${domain}`)
}
