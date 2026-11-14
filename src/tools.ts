/**
 * Tool definitions for dsh-netdoctor: six read-only network probes exposed to
 * every agent via defineTool. Each tool has a strict JSON-schema parameter
 * surface and a compact text renderer.
 *
 * @module dsh-netdoctor/tools
 */

import { defineTool, type ToolDefinition } from '@deepseek-ai/dsh-tools'
import { dnsLookup, renderAnswer, type DnsAnswer, type DnsRecordType } from './dns.ts'
import { pingHost, type PingResult } from './ping.ts'
import { checkPort, type PortResult } from './port.ts'
import { checkTls, type TlsResult } from './tls.ts'
import { getPublicIp, type IpGeoResult } from './ip.ts'
import { traceRoute, type TraceResult } from './route.ts'
import { whoisLookup, type WhoisResult } from './whois.ts'
import { dnsPropagation, type PropagationResult } from './propagation.ts'
import { checkHttp, DEFAULT_BODY_LIMIT_BYTES, DEFAULT_MAX_REDIRECTS, type HttpResult } from './http.ts'
import { emailDns, MAX_DKIM_SELECTORS, type EmailDnsResult } from './email.ts'
import type { ResolvedConfig } from './index.ts'

export interface ToolSet {
  dns_lookup: ToolDefinition
  dns_propagation: ToolDefinition
  email_dns: ToolDefinition
  ping_host: ToolDefinition
  check_port: ToolDefinition
  check_tls: ToolDefinition
  check_http: ToolDefinition
  trace_route: ToolDefinition
  my_ip: ToolDefinition
  whois: ToolDefinition
}

const DNS_RECORDS: readonly DnsRecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'CAA']

function renderDns(value: unknown): string {
  const result = value as { host: string; record: string; server: string; answers: DnsAnswer[] }
  if (result.answers.length === 0) {
    return `no ${result.record} records found for ${result.host} (server: ${result.server})`
  }
  return `${result.answers.length} ${result.record} record(s) for ${result.host} (server: ${result.server}):\n${result.answers.map((a) => `  ${renderAnswer(a)}`).join('\n')}`
}

function renderPropagation(value: unknown): string {
  const result = value as PropagationResult
  const verdict = result.consistent
    ? 'all answered resolvers agree'
    : `${result.groups.length} distinct answer set(s)`
  const lines = [
    `dns propagation for ${result.host} ${result.record} across ${result.resolvers} resolvers: `
    + `${result.responded} answered, ${verdict}`,
  ]
  for (const group of result.groups) {
    const who = group.resolvers.join(', ')
    lines.push(result.groups.length > 1 ? `  [${group.resolvers.length}/${result.responded}] ${who}:` : `  ${who}:`)
    if (group.answers.length === 0) {
      lines.push('      (no records in the answer)')
    } else {
      for (const answer of group.answers) lines.push(`      ${renderAnswer(answer)}`)
    }
  }
  for (const probe of result.probes) {
    if (probe.status === 'error') {
      lines.push(`  ⚠️ ${probe.label} (${probe.server}): ${probe.error ?? 'no answer'}`)
    }
  }
  if (result.note !== undefined) lines.push(`  note: ${result.note}`)
  return lines.join('\n')
}

function renderPing(value: unknown): string {
  const result = value as PingResult
  const addr = result.resolvedAddress === undefined ? result.host : `${result.host} (${result.resolvedAddress})`
  const rtt = result.rttMs === undefined ? '' : `  rtt: min ${result.rttMs.min} ms / avg ${result.rttMs.avg} ms / max ${result.rttMs.max} ms`
  const note = result.note === undefined ? '' : `\n  note: ${result.note}`
  return `${addr}: ${result.received}/${result.transmitted} replies, ${result.lossPercent}% loss${rtt}${note}`
}

function renderPort(value: unknown): string {
  const result = value as PortResult
  const timing = result.connectMs === undefined ? '' : ` in ${result.connectMs} ms`
  const detail = result.detail === undefined ? '' : ` — ${result.detail}`
  return `${result.host}:${result.port} is ${result.status}${timing}${detail}`
}

function renderTls(value: unknown): string {
  const result = value as TlsResult
  if (!result.connected || result.cert === undefined) {
    return `${result.host}:${result.port} — no TLS session established${result.detail === undefined ? '' : ` (${result.detail})`}`
  }
  const lines = [
    `${result.host}:${result.port} — TLS ${result.protocol ?? 'unknown'} / ${result.cipher ?? 'unknown cipher'}`,
    `  subject: ${result.cert.subject}${result.cert.altNames.length > 0 ? `  [SANs: ${result.cert.altNames.join(', ')}]` : ''}`,
    `  issuer: ${result.cert.issuer}`,
    `  valid: ${result.cert.validFrom} → ${result.cert.validTo}  (${result.cert.daysRemaining} days remaining)`,
    `  verified chain: ${result.authorized === true ? 'yes' : 'no'}${result.authorizationError === undefined ? '' : ` — ${result.authorizationError}`}`,
    `  sha256 fingerprint: ${result.cert.fingerprint256}`,
  ]
  return lines.join('\n')
}

function renderHttp(value: unknown): string {
  const result = value as HttpResult
  if (result.error !== undefined) {
    return `check_http ${result.url}: ${result.error}`
  }
  const lines = [
    `${result.status} ${result.statusText} — ${result.finalUrl} (HTTP/${result.httpVersion ?? 'unknown'} ${result.method}, ${result.timing.totalMs} ms)`,
  ]
  for (const hop of result.redirectChain) lines.push(`  → ${hop.status} ${hop.location}`)
  const marks: string[] = []
  if (result.timing.dnsMs !== undefined) marks.push(`dns ${result.timing.dnsMs} ms`)
  if (result.timing.connectMs !== undefined) marks.push(`connect ${result.timing.connectMs} ms`)
  if (result.timing.tlsMs !== undefined) marks.push(`tls ${result.timing.tlsMs} ms`)
  if (result.timing.ttfbMs !== undefined) marks.push(`ttfb ${result.timing.ttfbMs} ms`)
  marks.push(`total ${result.timing.totalMs} ms`)
  lines.push(`  timing: ${marks.join(' / ')}`)
  for (const [name, headerValue] of Object.entries(result.headers)) lines.push(`  ${name}: ${headerValue}`)
  const body = `  body: ${result.bodyBytes} byte(s) read${result.bodyTruncated ? ' (truncated at the body limit)' : ''}`
  const cookies = result.setCookieCount > 0 ? `, ${result.setCookieCount} Set-Cookie header(s) (values not shown)` : ''
  lines.push(body + cookies)
  if (result.note !== undefined) lines.push(`  note: ${result.note}`)
  return lines.join('\n')
}

function renderTrace(value: unknown): string {
  const result = value as TraceResult
  const lines = result.hops.map((hop) => {
    const target = hop.host ?? hop.address ?? '*'
    const rtts = hop.rttsMs.length > 0 ? hop.rttsMs.map((ms) => `${ms} ms`).join(' ') : 'no reply'
    return `  ${hop.hop}  ${target}  ${rtts}`
  })
  const status = result.complete ? 'target reached' : 'target not reached within max hops'
  const note = result.note === undefined ? '' : `\n  note: ${result.note}`
  return `traceroute to ${result.host} (${result.hops.length} hops, ${status}):\n${lines.join('\n')}${note}`
}

function renderIp(value: unknown): string {
  const result = value as IpGeoResult
  if (result.geo === undefined) {
    const note = result.geoNote === undefined ? '' : ` (${result.geoNote})`
    return `public IP: ${result.ip}${note}`
  }
  const geo = result.geo
  return [
    `public IP: ${result.ip}`,
    `  location: ${[geo.country, geo.region, geo.city].filter((part) => part !== '').join(', ')} (${geo.timezone})`,
    `  network: ${geo.isp}${geo.org !== '' && geo.org !== geo.isp ? ` / ${geo.org}` : ''} [${geo.as}]`,
    `  coordinates: ${geo.lat}, ${geo.lon}`,
  ].join('\n')
}

function renderWhois(value: unknown): string {
  const result = value as WhoisResult
  if (result.error !== undefined) {
    return `whois ${result.domain}: ${result.error}`
  }
  const summary = result.summary
  const lines = [`whois ${result.domain} (server: ${result.server}${result.rawTruncated ? ', raw truncated' : ''}):`]
  if (summary.registrar !== undefined) lines.push(`  registrar: ${summary.registrar}`)
  if (summary.createdDate !== undefined) lines.push(`  created: ${summary.createdDate}`)
  if (summary.updatedDate !== undefined) lines.push(`  updated: ${summary.updatedDate}`)
  if (summary.expiryDate !== undefined) lines.push(`  expiry: ${summary.expiryDate}`)
  if (summary.statuses.length > 0) lines.push(`  status: ${summary.statuses.join(', ')}`)
  if (summary.nameServers.length > 0) lines.push(`  nameservers: ${summary.nameServers.join(', ')}`)
  return lines.join('\n')
}

function renderEmail(value: unknown): string {
  const result = value as EmailDnsResult
  const lines: string[] = []
  if (result.nullMx) {
    lines.push(`email DNS for ${result.domain}: mail is not accepted (null MX "0 .")`)
  } else if (result.mx.length > 0) {
    lines.push(`email DNS for ${result.domain}: ${result.mx.length} MX record(s)`)
    for (const record of result.mx) lines.push(`  ${record.priority} ${record.exchange}`)
  } else {
    lines.push(`email DNS for ${result.domain}: no MX records${result.implicitMx ? ' (A/AAAA fallback)' : ''}`)
    for (const address of result.fallbackAddresses) lines.push(`  ${address} [implicit MX]`)
  }
  const spf = result.spf
  if (spf.found) {
    const verdict = spf.allQualifier === undefined ? 'no all mechanism' : `${spf.allQualifier}all`
    lines.push(`  spf: ${spf.selected ?? ''}`)
    lines.push(`    ${spf.dnsLookups}/${spf.lookupLimit} DNS-querying terms at this level, ${verdict}${spf.includes.length > 0 ? `, includes: ${spf.includes.join(', ')}` : ''}`)
  } else {
    lines.push(`  spf: ${spf.error === undefined ? 'none' : `lookup failed — ${spf.error}`}`)
  }
  const dmarc = result.dmarc
  if (dmarc.found) {
    const extras: string[] = []
    if (dmarc.percentage !== undefined) extras.push(`pct=${dmarc.percentage}`)
    if (dmarc.reportingUris.length > 0) extras.push(`rua ${dmarc.reportingUris.length}`)
    lines.push(`  dmarc: p=${dmarc.policy ?? '(missing)'}${extras.length > 0 ? ` (${extras.join(', ')})` : ''}${dmarc.usable ? '' : ' [record not usable]'}`)
  } else {
    lines.push(`  dmarc: ${dmarc.error === undefined ? 'none' : `lookup failed — ${dmarc.error}`}`)
  }
  for (const report of result.dkim) {
    const state = report.error !== undefined
      ? `lookup failed — ${report.error}`
      : report.found
        ? `${report.keyType === undefined ? 'key present' : `${report.keyType} key present`}${report.revoked ? ' (revoked)' : ''}`
        : 'no key'
    lines.push(`  dkim ${report.selector}: ${state}`)
  }
  if (result.findings.length > 0) {
    const marks: Record<string, string> = { error: '✗', warning: '⚠️', info: 'ℹ️' }
    lines.push('  findings:')
    for (const finding of result.findings) lines.push(`    ${marks[finding.severity] ?? '-'} ${finding.code}: ${finding.message}`)
  }
  if (result.note !== undefined) lines.push(`  note: ${result.note}`)
  return lines.join('\n')
}

/** Build all ten tool definitions from the resolved config. */
export function buildNetdoctorTools(config: ResolvedConfig): ToolSet {
  const dns_lookup = defineTool({
    name: 'dns_lookup',
    description: 'Query DNS records for a hostname or IP address (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA) using the '
      + 'system resolver or a custom nameserver — useful for checking what the public DNS actually returns and for '
      + 'testing DNS propagation. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname or IP address to look up (e.g. "example.com" or "1.1.1.1" for PTR).' },
      record: { type: 'string', enum: [...DNS_RECORDS], description: 'Record type to query (default A).' },
      server: { type: 'string', description: 'Optional nameserver to query directly (IPv4/IPv6), e.g. "8.8.8.8". Omit to use the system resolver.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          record: { type: 'string', required: true },
          server: { type: 'string', required: true },
          answers: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
        },
      },
      render: (_args: { host: string }, value: unknown) => [{ type: 'text', text: renderDns(value) }],
    },
    async execute(args: { host: string; record?: DnsRecordType; server?: string }) {
      return dnsLookup(args.host, args.record ?? 'A', args.server)
    },
  })

  const dns_propagation = defineTool({
    name: 'dns_propagation',
    description: 'Query the same DNS record through several public resolvers in parallel and report where they agree and '
      + 'where they differ — the fast way to judge whether a recent DNS change has propagated. Answers are grouped by '
      + 'record content, so "4 of 6 agree" is counted from the data, and resolvers that fail or time out are reported as '
      + 'failed instead of being folded into the majority. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname or IP address to look up.' },
      record: { type: 'string', enum: [...DNS_RECORDS], description: 'Record type to query (default A).' },
      resolvers: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional resolver IPs to probe instead of the built-in public set (Google 8.8.8.8, Cloudflare 1.1.1.1, '
          + 'Quad9 9.9.9.9, OpenDNS 208.67.222.222, Level3 4.2.2.1, DNS.SB 185.222.222.222); at most 10, IP literals only.',
      },
      timeoutMs: { type: 'number', description: `Per-resolver answer deadline in ms (100–60000, default ${config.propagationTimeoutMs}).` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          record: { type: 'string', required: true },
          resolvers: { type: 'number', required: true },
          responded: { type: 'number', required: true },
          failed: { type: 'number', required: true },
          consistent: { type: 'boolean', required: true },
          consensus: {
            type: 'object',
            additionalProperties: false,
            properties: {
              fingerprint: { type: 'string', required: true },
              resolvers: { type: 'array', required: true, items: { type: 'string' } },
            },
          },
          groups: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          probes: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          note: { type: 'string' },
        },
      },
      render: (_args: { host: string }, value: unknown) => [{ type: 'text', text: renderPropagation(value) }],
    },
    async execute(args: { host: string; record?: DnsRecordType; resolvers?: string[]; timeoutMs?: number }) {
      const options: { resolvers?: string[]; timeoutMs?: number } = { timeoutMs: args.timeoutMs ?? config.propagationTimeoutMs }
      if (args.resolvers !== undefined) options.resolvers = args.resolvers
      return dnsPropagation(args.host, args.record ?? 'A', options)
    },
  })

  const ping_host = defineTool({
    name: 'ping_host',
    description: 'Send ICMP echo requests to a host via the system ping utility and report reachability, packet '
      + 'loss and round-trip times (min/avg/max). The best first check for "is this host reachable at all". Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname or IP address to ping.' },
      count: { type: 'number', description: `Number of echo requests (1–20, default ${config.pingCount}).` },
      timeoutSec: { type: 'number', description: `Seconds to wait per reply (1–60, default ${config.pingTimeoutSec}).` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          resolvedAddress: { type: 'string' },
          transmitted: { type: 'number', required: true },
          received: { type: 'number', required: true },
          lossPercent: { type: 'number', required: true },
          rttMs: {
            type: 'object',
            additionalProperties: false,
            properties: {
              min: { type: 'number', required: true },
              avg: { type: 'number', required: true },
              max: { type: 'number', required: true },
            },
          },
          note: { type: 'string' },
          raw: { type: 'string' },
        },
      },
      render: (_args: { host: string }, value: unknown) => [{ type: 'text', text: renderPing(value) }],
    },
    async execute(args: { host: string; count?: number; timeoutSec?: number }) {
      return pingHost(args.host, args.count ?? config.pingCount, args.timeoutSec ?? config.pingTimeoutSec)
    },
  })

  const check_port = defineTool({
    name: 'check_port',
    description: 'Test whether a TCP port on a host is open, closed, or filtered by attempting a raw TCP connect. '
      + 'Useful for debugging "connection refused", firewalls and service availability. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname or IP address of the target.' },
      port: { type: 'number', required: true, description: 'TCP port to test (1–65535).' },
      timeoutMs: { type: 'number', description: `Connect timeout in ms (100–60000, default ${config.timeoutMs}).` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          port: { type: 'number', required: true },
          status: { type: 'string', required: true, enum: ['open', 'closed', 'filtered', 'unreachable'] },
          connectMs: { type: 'number' },
          detail: { type: 'string' },
        },
      },
      render: (_args: { host: string; port: number }, value: unknown) => [{ type: 'text', text: renderPort(value) }],
    },
    async execute(args: { host: string; port: number; timeoutMs?: number }) {
      return checkPort(args.host, args.port, args.timeoutMs ?? config.timeoutMs)
    },
  })

  const check_tls = defineTool({
    name: 'check_tls',
    description: 'Perform a real TLS handshake with a host and inspect the certificate it presents: protocol and '
      + 'cipher negotiated, subject, issuer, validity window, days until expiry, SANs and SHA-256 fingerprint. '
      + 'Certificates are inspected but never trusted, so expired or self-signed certificates can be diagnosed. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname to connect to (also used as SNI).' },
      port: { type: 'number', description: 'TLS port (default 443).' },
      timeoutMs: { type: 'number', description: `Handshake timeout in ms (100–60000, default ${config.timeoutMs}).` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          port: { type: 'number', required: true },
          connected: { type: 'boolean', required: true },
          protocol: { type: 'string' },
          cipher: { type: 'string' },
          authorized: { type: 'boolean' },
          authorizationError: { type: 'string' },
          cert: {
            type: 'object',
            additionalProperties: false,
            properties: {
              subject: { type: 'string', required: true },
              issuer: { type: 'string', required: true },
              validFrom: { type: 'string', required: true },
              validTo: { type: 'string', required: true },
              daysRemaining: { type: 'number', required: true },
              altNames: { type: 'array', required: true, items: { type: 'string' } },
              serialNumber: { type: 'string', required: true },
              fingerprint256: { type: 'string', required: true },
            },
          },
          detail: { type: 'string' },
        },
      },
      render: (_args: { host: string }, value: unknown) => [{ type: 'text', text: renderTls(value) }],
    },
    async execute(args: { host: string; port?: number; timeoutMs?: number }) {
      return checkTls(args.host, args.port ?? 443, args.timeoutMs ?? config.timeoutMs)
    },
  })

  const check_http = defineTool({
    name: 'check_http',
    description: 'Fetch one HTTP(S) URL the way a browser would — following redirects — and report the status line, '
      + 'the redirect chain, which layer is slow (DNS / TCP connect / TLS handshake / time to first byte / total, '
      + 'measured on the socket), the response headers that matter (content-type, cache-control, and the security '
      + 'headers HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / CORS) and how much body '
      + 'was read. Redirects are followed only to http/https targets, and cookie values are counted, never shown. '
      + 'Read-only.',
    parameters: {
      url: { type: 'string', required: true, description: 'Absolute http:// or https:// URL to check (credentials in the URL are rejected).' },
      method: { type: 'string', enum: ['GET', 'HEAD'], description: 'Request method (default GET). HEAD skips the body.' },
      maxRedirects: { type: 'number', description: `How many redirects to follow (0–10, default ${DEFAULT_MAX_REDIRECTS}).` },
      bodyLimitBytes: { type: 'number', description: `Stop reading the body after this many bytes (1–1000000, default ${DEFAULT_BODY_LIMIT_BYTES}).` },
      timeoutMs: { type: 'number', description: `Per-request deadline in ms (100–60000, default ${config.httpTimeoutMs}).` },
      insecure: { type: 'boolean', description: 'Accept an invalid certificate instead of reporting it (default false; for inspecting a known-bad endpoint).' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          url: { type: 'string', required: true },
          finalUrl: { type: 'string', required: true },
          method: { type: 'string', required: true, enum: ['GET', 'HEAD'] },
          reachable: { type: 'boolean', required: true },
          status: { type: 'number', required: true },
          statusText: { type: 'string', required: true },
          httpVersion: { type: 'string' },
          redirected: { type: 'number', required: true },
          redirectChain: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          headers: { type: 'object', required: true, additionalProperties: true },
          headersTruncated: { type: 'number', required: true },
          setCookieCount: { type: 'number', required: true },
          bodyBytes: { type: 'number', required: true },
          bodyTruncated: { type: 'boolean', required: true },
          timing: {
            type: 'object',
            required: true,
            additionalProperties: false,
            properties: {
              dnsMs: { type: 'number' },
              connectMs: { type: 'number' },
              tlsMs: { type: 'number' },
              ttfbMs: { type: 'number' },
              totalMs: { type: 'number', required: true },
            },
          },
          note: { type: 'string' },
          error: { type: 'string' },
        },
      },
      render: (_args: { url: string }, value: unknown) => [{ type: 'text', text: renderHttp(value) }],
    },
    async execute(args: {
      url: string
      method?: 'GET' | 'HEAD'
      maxRedirects?: number
      bodyLimitBytes?: number
      timeoutMs?: number
      insecure?: boolean
    }) {
      const options: Parameters<typeof checkHttp>[1] = { timeoutMs: args.timeoutMs ?? config.httpTimeoutMs }
      if (args.method !== undefined) options.method = args.method
      if (args.maxRedirects !== undefined) options.maxRedirects = args.maxRedirects
      if (args.bodyLimitBytes !== undefined) options.bodyLimitBytes = args.bodyLimitBytes
      if (args.insecure !== undefined) options.insecure = args.insecure
      return checkHttp(args.url, options)
    },
  })

  const trace_route = defineTool({
    name: 'trace_route',
    description: 'Trace the network path to a host hop by hop using the system traceroute utility (tracert on '
      + 'Windows) and report each hop with its address and per-hop round-trip times. Useful for finding where '
      + 'packets stall. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Hostname or IP address to trace to.' },
      maxHops: { type: 'number', description: `Maximum hops to probe (1–64, default ${config.maxHops}).` },
      timeoutSec: { type: 'number', description: `Seconds to wait per hop (1–30, default ${config.traceTimeoutSec}).` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          maxHops: { type: 'number', required: true },
          complete: { type: 'boolean', required: true },
          note: { type: 'string' },
          hops: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                hop: { type: 'number', required: true },
                host: { type: 'string' },
                address: { type: 'string' },
                rttsMs: { type: 'array', required: true, items: { type: 'number' } },
                raw: { type: 'string', required: true },
              },
            },
          },
          raw: { type: 'string' },
        },
      },
      render: (_args: { host: string }, value: unknown) => [{ type: 'text', text: renderTrace(value) }],
    },
    async execute(args: { host: string; maxHops?: number; timeoutSec?: number }) {
      return traceRoute(args.host, args.maxHops ?? config.maxHops, args.timeoutSec ?? config.traceTimeoutSec)
    },
  })

  const my_ip = defineTool({
    name: 'my_ip',
    description: 'Report this machine\'s public IP address, optionally with geo info (country, region, city, ISP, '
      + 'AS, timezone, coordinates) from ip-api.com\'s free keyless endpoint. Plain-IP fallback if geo is unavailable '
      + 'or disabled. Read-only.',
    parameters: {
      includeGeo: { type: 'boolean', description: `Attach geo info (default ${config.includeGeo}); set false for plain IP only.` },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ip: { type: 'string', required: true },
          geo: {
            type: 'object',
            additionalProperties: false,
            properties: {
              country: { type: 'string', required: true },
              region: { type: 'string', required: true },
              city: { type: 'string', required: true },
              isp: { type: 'string', required: true },
              org: { type: 'string', required: true },
              as: { type: 'string', required: true },
              timezone: { type: 'string', required: true },
              lat: { type: 'number', required: true },
              lon: { type: 'number', required: true },
            },
          },
          geoNote: { type: 'string' },
        },
      },
      render: (_args: { includeGeo?: boolean }, value: unknown) => [{ type: 'text', text: renderIp(value) }],
    },
    async execute(args: { includeGeo?: boolean }) {
      return getPublicIp(args.includeGeo ?? config.includeGeo, config.httpTimeoutMs)
    },
  })

  const whois = defineTool({
    name: 'whois',
    description: 'Query the WHOIS registry for a domain name or IP address over the classic TCP port 43 protocol. '
      + 'Automatically discovers the right registry server via the whois.iana.org referral chain, then returns the raw '
      + 'WHOIS text plus a best-effort structured summary (registrar, statuses, created/updated/expiry dates, '
      + 'nameservers). Useful for checking domain registration, expiry and nameserver delegation. Read-only.',
    parameters: {
      domain: { type: 'string', required: true, description: 'Domain name or IP address to look up (e.g. "example.com" or "8.8.8.8").' },
      server: { type: 'string', description: 'Optional WHOIS server to query directly (hostname), skipping IANA discovery, e.g. "whois.verisign-grs.com".' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domain: { type: 'string', required: true },
          server: { type: 'string', required: true },
          raw: { type: 'string', required: true },
          rawTruncated: { type: 'boolean', required: true },
          summary: {
            type: 'object',
            additionalProperties: false,
            properties: {
              registrar: { type: 'string' },
              statuses: { type: 'array', required: true, items: { type: 'string' } },
              createdDate: { type: 'string' },
              updatedDate: { type: 'string' },
              expiryDate: { type: 'string' },
              nameServers: { type: 'array', required: true, items: { type: 'string' } },
            },
          },
          error: { type: 'string' },
        },
      },
      render: (_args: { domain: string }, value: unknown) => [{ type: 'text', text: renderWhois(value) }],
    },
    async execute(args: { domain: string; server?: string }) {
      return whoisLookup(args.domain, args.server, config.whoisTimeoutMs)
    },
  })

  const email_dns = defineTool({
    name: 'email_dns',
    description: 'Check whether a domain is set up to send and receive mail, using DNS only: MX records (including the '
      + 'null-MX "0 ." signal that a domain accepts no mail, and the RFC 5321 A/AAAA fallback when MX is absent), the '
      + 'SPF record parsed into mechanisms with its DNS-lookup budget (RFC 7208 counts at most 10 per evaluation) and '
      + 'final "all" qualifier, the DMARC record at _dmarc.<domain> parsed into tags (p / sp / pct / rua / ruf), and any '
      + 'DKIM selectors you name. Every problem is returned as a severity-coded finding instead of a boolean, and a '
      + 'failed lookup is reported as a failure rather than as "no records". Read-only.',
    parameters: {
      domain: { type: 'string', required: true, description: 'Domain to check, e.g. "example.com" (the domain itself, not an address).' },
      dkimSelectors: {
        type: 'array',
        items: { type: 'string' },
        description: `Selectors to probe at <selector>._domainkey.<domain> (at most ${MAX_DKIM_SELECTORS}). Selectors cannot be `
          + 'discovered via DNS — take one from a message header "s=" tag or from your provider\'s docs.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domain: { type: 'string', required: true },
          mailAccepted: { type: 'boolean', required: true },
          mx: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                exchange: { type: 'string', required: true },
                priority: { type: 'number', required: true },
              },
            },
          },
          nullMx: { type: 'boolean', required: true },
          implicitMx: { type: 'boolean', required: true },
          fallbackAddresses: { type: 'array', required: true, items: { type: 'string' } },
          mxError: { type: 'string' },
          spf: {
            type: 'object',
            required: true,
            additionalProperties: false,
            properties: {
              found: { type: 'boolean', required: true },
              records: { type: 'array', required: true, items: { type: 'string' } },
              selected: { type: 'string' },
              multiple: { type: 'boolean', required: true },
              terms: { type: 'array', required: true, items: { type: 'string' } },
              dnsLookups: { type: 'number', required: true },
              lookupLimit: { type: 'number', required: true },
              exceedsLimit: { type: 'boolean', required: true },
              allQualifier: { type: 'string' },
              allIsLast: { type: 'boolean', required: true },
              includes: { type: 'array', required: true, items: { type: 'string' } },
              redirect: { type: 'string' },
              unknownTerms: { type: 'array', required: true, items: { type: 'string' } },
              error: { type: 'string' },
            },
          },
          dmarc: {
            type: 'object',
            required: true,
            additionalProperties: false,
            properties: {
              found: { type: 'boolean', required: true },
              name: { type: 'string', required: true },
              records: { type: 'array', required: true, items: { type: 'string' } },
              selected: { type: 'string' },
              usable: { type: 'boolean', required: true },
              versionFirst: { type: 'boolean', required: true },
              tags: { type: 'object', required: true, additionalProperties: true },
              policy: { type: 'string' },
              subdomainPolicy: { type: 'string' },
              percentage: { type: 'number' },
              reportingUris: { type: 'array', required: true, items: { type: 'string' } },
              forensicUris: { type: 'array', required: true, items: { type: 'string' } },
              duplicateTags: { type: 'array', required: true, items: { type: 'string' } },
              error: { type: 'string' },
            },
          },
          dkim: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                selector: { type: 'string', required: true },
                name: { type: 'string', required: true },
                found: { type: 'boolean', required: true },
                revoked: { type: 'boolean', required: true },
                keyType: { type: 'string' },
                error: { type: 'string' },
              },
            },
          },
          findings: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                severity: { type: 'string', required: true, enum: ['error', 'warning', 'info'] },
                code: { type: 'string', required: true },
                message: { type: 'string', required: true },
              },
            },
          },
          note: { type: 'string' },
        },
      },
      render: (_args: { domain: string }, value: unknown) => [{ type: 'text', text: renderEmail(value) }],
    },
    async execute(args: { domain: string; dkimSelectors?: string[] }) {
      const options: Parameters<typeof emailDns>[1] = {}
      if (args.dkimSelectors !== undefined) options.dkimSelectors = args.dkimSelectors
      return emailDns(args.domain, options)
    },
  })

  return { dns_lookup, dns_propagation, email_dns, ping_host, check_port, check_tls, check_http, trace_route, my_ip, whois }
}
