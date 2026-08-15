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
import z from '@deepseek-ai/schemastery';
import { buildNetdoctorTools } from "./tools.js";
/** Stable Cordis plugin name (also the config key under `plugins:`). */
export const name = 'dsh-netdoctor';
/** Services required before tool registration can start. */
export const inject = ['agents', 'tools'];
export const Config = z.object({
    timeoutMs: z.number().min(100).max(60_000).default(3_000),
    pingCount: z.number().step(1).min(1).max(20).default(4),
    pingTimeoutSec: z.number().min(1).max(60).default(2),
    maxHops: z.number().step(1).min(1).max(64).default(20),
    traceTimeoutSec: z.number().min(1).max(30).default(2),
    includeGeo: z.boolean().default(true),
    httpTimeoutMs: z.number().min(1_000).max(60_000).default(5_000),
});
/** Resolve loader config into the effective runtime config. */
export function resolveConfig(config) {
    return {
        timeoutMs: config.timeoutMs ?? 3_000,
        pingCount: config.pingCount ?? 4,
        pingTimeoutSec: config.pingTimeoutSec ?? 2,
        maxHops: config.maxHops ?? 20,
        traceTimeoutSec: config.traceTimeoutSec ?? 2,
        includeGeo: config.includeGeo ?? true,
        httpTimeoutMs: config.httpTimeoutMs ?? 5_000,
    };
}
/** Register every netdoctor tool on one agent; returns the disposer. */
function decorate(agent, tools) {
    const disposers = Object.values(tools).map((definition) => agent.ctx.tools.register(definition));
    return () => {
        for (const dispose of disposers) {
            try {
                dispose();
            }
            catch {
                // already disposed
            }
        }
    };
}
/** Mount the netdoctor tools on every live agent and every future one. */
export function apply(ctx, config) {
    const resolved = resolveConfig(config);
    const tools = buildNetdoctorTools(resolved);
    const disposers = new Set();
    const decorateAgent = (agent) => {
        try {
            disposers.add(decorate(agent, tools));
        }
        catch (error) {
            ctx.logger('netdoctor').warn(`tool registration for agent ${agent.id} failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    };
    for (const agent of ctx.agents.list())
        decorateAgent(agent);
    const off = ctx.on('agent/created', ({ agent }) => decorateAgent(agent));
    ctx.effect(() => () => {
        off();
        for (const dispose of disposers) {
            try {
                dispose();
            }
            catch {
                // already disposed
            }
        }
        disposers.clear();
    });
}
//# sourceMappingURL=index.js.map