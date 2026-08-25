/**
 * dsh-netdoctor — network diagnostics toolbox for DeepSeek Harness.
 *
 * Seven read-only probes, zero runtime dependencies (node built-ins only):
 *   dns_lookup   — DNS records (A/AAAA/CNAME/MX/TXT/NS/SOA/SRV/PTR/CAA), optional custom nameserver
 *   ping_host    — ICMP ping via the system ping utility, parsed summary
 *   check_port   — TCP connect probe: open / closed / filtered
 *   check_tls    — TLS handshake + leaf certificate identity, validity, days to expiry
 *   trace_route  — traceroute via the system traceroute/tracert utility
 *   my_ip        — public IP address with optional geo info (ip-api.com, keyless)
 *   whois        — WHOIS registry lookup via TCP port 43 with IANA referral discovery
 *
 * Safety model: every probe is read-only. External binaries (ping, traceroute,
 * tracert) are invoked with fixed argument arrays and never through a shell,
 * all targets are validated, and every operation has a hard timeout.
 *
 * @module dsh-netdoctor
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import z from '@deepseek-ai/schemastery'
import { buildNetdoctorTools, type ToolSet } from './tools.ts'

/** Stable Cordis plugin name (also the config key under `plugins:`). */
export const name = 'dsh-netdoctor'

/** Services required before tool registration can start. */
export const inject = ['agents', 'tools']

/** Plugin configuration, resolved with defaults by the loader. */
export interface Config {
  /** Default timeout for TCP/TLS probes (100–60000 ms). */
  timeoutMs?: number
  /** Default ICMP ping count (1–20). */
  pingCount?: number
  /** Default per-reply wait for ping, seconds (1–60). */
  pingTimeoutSec?: number
  /** Default maximum hops for traceroute (1–64). */
  maxHops?: number
  /** Per-hop wait for traceroute, seconds (1–30). */
  traceTimeoutSec?: number
  /** Attach geo info to my_ip results (privacy: set false for plain IP only). */
  includeGeo?: boolean
  /** Timeout for the my_ip HTTP lookups (1000–60000 ms). */
  httpTimeoutMs?: number
  /** Timeout for WHOIS queries over TCP port 43 (1000–60000 ms). */
  whoisTimeoutMs?: number
}

export const Config: z<Config> = z.object({
  timeoutMs: z.number().min(100).max(60_000).default(3_000),
  pingCount: z.number().step(1).min(1).max(20).default(4),
  pingTimeoutSec: z.number().min(1).max(60).default(2),
  maxHops: z.number().step(1).min(1).max(64).default(20),
  traceTimeoutSec: z.number().min(1).max(30).default(2),
  includeGeo: z.boolean().default(true),
  httpTimeoutMs: z.number().min(1_000).max(60_000).default(5_000),
  whoisTimeoutMs: z.number().min(1_000).max(60_000).default(5_000),
})

/** Config with every default resolved (all fields guaranteed). */
export interface ResolvedConfig {
  timeoutMs: number
  pingCount: number
  pingTimeoutSec: number
  maxHops: number
  traceTimeoutSec: number
  includeGeo: boolean
  httpTimeoutMs: number
  whoisTimeoutMs: number
}

/** Resolve loader config into the effective runtime config. */
export function resolveConfig(config: Config): ResolvedConfig {
  return {
    timeoutMs: config.timeoutMs ?? 3_000,
    pingCount: config.pingCount ?? 4,
    pingTimeoutSec: config.pingTimeoutSec ?? 2,
    maxHops: config.maxHops ?? 20,
    traceTimeoutSec: config.traceTimeoutSec ?? 2,
    includeGeo: config.includeGeo ?? true,
    httpTimeoutMs: config.httpTimeoutMs ?? 5_000,
    whoisTimeoutMs: config.whoisTimeoutMs ?? 5_000,
  }
}

/** Register every netdoctor tool on one agent; returns the disposer. */
function decorate(agent: Agent, tools: ToolSet): () => void {
  const disposers = Object.values(tools).map((definition) => agent.ctx.tools.register(definition))
  return () => {
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // already disposed
      }
    }
  }
}

/** Mount the netdoctor tools on every live agent and every future one. */
export function apply(ctx: Context, config: Config): void {
  const resolved = resolveConfig(config)
  const tools = buildNetdoctorTools(resolved)
  const disposers = new Set<() => void>()

  const decorateAgent = (agent: Agent): void => {
    try {
      disposers.add(decorate(agent, tools))
    } catch (error) {
      ctx.logger('netdoctor').warn(`tool registration for agent ${agent.id} failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  for (const agent of ctx.agents.list()) decorateAgent(agent)
  const off = ctx.on('agent/created', ({ agent }) => decorateAgent(agent))

  ctx.effect(() => () => {
    off()
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // already disposed
      }
    }
    disposers.clear()
  })
}
