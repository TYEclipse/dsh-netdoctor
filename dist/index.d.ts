/**
 * dsh-netdoctor — network diagnostics toolbox for DeepSeek Harness.
 *
 * Six read-only probes, zero runtime dependencies (node built-ins only):
 *   dns_lookup   — DNS records (A/AAAA/CNAME/MX/TXT/NS/SRV/PTR), optional custom nameserver
 *   ping_host    — ICMP ping via the system ping utility, parsed summary
 *   check_port   — TCP connect probe: open / closed / filtered
 *   check_tls    — TLS handshake + leaf certificate identity, validity, days to expiry
 *   trace_route  — traceroute via the system traceroute/tracert utility
 *   my_ip        — public IP address with optional geo info (ip-api.com, keyless)
 *
 * Safety model: every probe is read-only. External binaries (ping, traceroute,
 * tracert) are invoked with fixed argument arrays and never through a shell,
 * all targets are validated, and every operation has a hard timeout.
 *
 * @module dsh-netdoctor
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
/** Stable Cordis plugin name (also the config key under `plugins:`). */
export declare const name = "dsh-netdoctor";
/** Services required before tool registration can start. */
export declare const inject: string[];
/** Plugin configuration, resolved with defaults by the loader. */
export interface Config {
    /** Default timeout for TCP/TLS probes (100–60000 ms). */
    timeoutMs?: number;
    /** Default ICMP ping count (1–20). */
    pingCount?: number;
    /** Default per-reply wait for ping, seconds (1–60). */
    pingTimeoutSec?: number;
    /** Default maximum hops for traceroute (1–64). */
    maxHops?: number;
    /** Per-hop wait for traceroute, seconds (1–30). */
    traceTimeoutSec?: number;
    /** Attach geo info to my_ip results (privacy: set false for plain IP only). */
    includeGeo?: boolean;
    /** Timeout for the my_ip HTTP lookups (1000–60000 ms). */
    httpTimeoutMs?: number;
}
export declare const Config: z<Config>;
/** Config with every default resolved (all fields guaranteed). */
export interface ResolvedConfig {
    timeoutMs: number;
    pingCount: number;
    pingTimeoutSec: number;
    maxHops: number;
    traceTimeoutSec: number;
    includeGeo: boolean;
    httpTimeoutMs: number;
}
/** Resolve loader config into the effective runtime config. */
export declare function resolveConfig(config: Config): ResolvedConfig;
/** Mount the netdoctor tools on every live agent and every future one. */
export declare function apply(ctx: Context, config: Config): void;
//# sourceMappingURL=index.d.ts.map