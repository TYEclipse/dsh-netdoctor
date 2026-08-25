/**
 * DNS record lookup via node:dns — no external services, supports querying an
 * alternative nameserver (handy for testing DNS propagation).
 *
 * @module dsh-netdoctor/dns
 */

import * as dns from 'node:dns/promises'
import type { JsonValue } from '@deepseek-ai/dsh-tools'
import { assertValidTarget } from './util.ts'

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'SRV' | 'PTR' | 'CAA'

export type DnsAnswer = {
  name: string
  type: string
  ttl: number
  data: Record<string, JsonValue>
}

export type DnsResult = {
  host: string
  record: DnsRecordType
  server: string
  answers: DnsAnswer[]
}

/** Render one answer for the text view. */
export function renderAnswer(answer: DnsAnswer): string {
  const { data } = answer
  if (answer.type === 'A' || answer.type === 'AAAA') {
    return `${answer.name} ${answer.type} ${String(data.address)} (ttl ${answer.ttl})`
  }
  if (answer.type === 'CNAME' || answer.type === 'NS' || answer.type === 'PTR') {
    return `${answer.name} ${answer.type} ${String(data.target)} (ttl ${answer.ttl})`
  }
  if (answer.type === 'MX') {
    return `${answer.name} MX ${String(data.priority)} ${String(data.exchange)} (ttl ${answer.ttl})`
  }
  if (answer.type === 'SRV') {
    return `${answer.name} SRV ${String(data.priority)} ${String(data.weight)} ${String(data.port)} ${String(data.target)} (ttl ${answer.ttl})`
  }
  if (answer.type === 'SOA') {
    return `${answer.name} SOA ns=${String(data.nsname)} mbox=${String(data.hostmaster)} serial=${String(data.serial)} refresh=${String(data.refresh)} retry=${String(data.retry)} expire=${String(data.expire)} minttl=${String(data.minttl)} (ttl ${answer.ttl})`
  }
  if (answer.type === 'CAA') {
    return `${answer.name} CAA ${String(data.critical)} ${String(data.tag)} "${String(data.value)}" (ttl ${answer.ttl})`
  }
  if (answer.type === 'TXT') {
    const entries = Array.isArray(data.entries) ? data.entries.map(String).join(' | ') : String(data.entries)
    return `${answer.name} TXT "${entries}" (ttl ${answer.ttl})`
  }
  return `${answer.name} ${answer.type} ${JSON.stringify(data)} (ttl ${answer.ttl})`
}

/**
 * Resolve DNS records for a host. `server` optionally targets a specific
 * nameserver (IPv4/IPv6); otherwise the system resolver is used.
 */
export async function dnsLookup(hostInput: string, record: DnsRecordType, server: string | undefined): Promise<DnsResult> {
  const host = assertValidTarget(hostInput)
  let resolver: dns.Resolver
  let serverUsed = 'system'
  if (server !== undefined && server.trim() !== '') {
    resolver = new dns.Resolver()
    resolver.setServers([server.trim()])
    serverUsed = server.trim()
  } else {
    resolver = new dns.Resolver()
  }

  const answers: DnsAnswer[] = []
  if (record === 'A') {
    const result = await resolver.resolve4(host, { ttl: true })
    for (const { address, ttl } of result) answers.push({ name: host, type: 'A', ttl, data: { address } })
  } else if (record === 'AAAA') {
    const result = await resolver.resolve6(host, { ttl: true })
    for (const { address, ttl } of result) answers.push({ name: host, type: 'AAAA', ttl, data: { address } })
  } else if (record === 'CNAME') {
    const result = await resolver.resolveCname(host)
    for (const target of result) answers.push({ name: host, type: 'CNAME', ttl: 0, data: { target } })
  } else if (record === 'MX') {
    const result = await resolver.resolveMx(host)
    for (const { exchange, priority } of result) answers.push({ name: host, type: 'MX', ttl: 0, data: { exchange, priority } })
  } else if (record === 'TXT') {
    const result = await resolver.resolveTxt(host)
    for (const entries of result) answers.push({ name: host, type: 'TXT', ttl: 0, data: { entries } })
  } else if (record === 'NS') {
    const result = await resolver.resolveNs(host)
    for (const target of result) answers.push({ name: host, type: 'NS', ttl: 0, data: { target } })
  } else if (record === 'SRV') {
    const result = await resolver.resolveSrv(host)
    for (const { name, port, priority, weight } of result) answers.push({ name: name ?? host, type: 'SRV', ttl: 0, data: { port, priority, weight, target: name } })
  } else if (record === 'SOA') {
    const { nsname, hostmaster, serial, refresh, retry, expire, minttl } = await resolver.resolveSoa(host)
    answers.push({ name: host, type: 'SOA', ttl: 0, data: { nsname, hostmaster, serial, refresh, retry, expire, minttl } })
  } else if (record === 'CAA') {
    const result = await resolver.resolveCaa(host)
    for (const { critical, issue, issuewild, iodef, contactemail, contactphone } of result) {
      const tag = issue !== undefined
        ? 'issue'
        : issuewild !== undefined
          ? 'issuewild'
          : iodef !== undefined
            ? 'iodef'
            : contactemail !== undefined
              ? 'contactemail'
              : contactphone !== undefined
                ? 'contactphone'
                : 'unknown'
      const value = issue ?? issuewild ?? iodef ?? contactemail ?? contactphone ?? ''
      answers.push({ name: host, type: 'CAA', ttl: 0, data: { critical, tag, value } })
    }
  } else if (record === 'PTR') {
    const result = await resolver.reverse(host)
    for (const target of result) answers.push({ name: host, type: 'PTR', ttl: 0, data: { target } })
  }

  return { host, record, server: serverUsed, answers }
}
