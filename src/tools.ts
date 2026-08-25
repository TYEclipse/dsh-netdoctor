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
import type { ResolvedConfig } from './index.ts'

export interface ToolSet {
  dns_lookup: ToolDefinition
  ping_host: ToolDefinition
  check_port: ToolDefinition
  check_tls: ToolDefinition
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

/** Build all seven tool definitions from the resolved config. */
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

  return { dns_lookup, ping_host, check_port, check_tls, trace_route, my_ip, whois }
}
