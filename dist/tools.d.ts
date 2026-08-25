/**
 * Tool definitions for dsh-netdoctor: six read-only network probes exposed to
 * every agent via defineTool. Each tool has a strict JSON-schema parameter
 * surface and a compact text renderer.
 *
 * @module dsh-netdoctor/tools
 */
import { type ToolDefinition } from '@deepseek-ai/dsh-tools';
import type { ResolvedConfig } from './index.ts';
export interface ToolSet {
    dns_lookup: ToolDefinition;
    ping_host: ToolDefinition;
    check_port: ToolDefinition;
    check_tls: ToolDefinition;
    trace_route: ToolDefinition;
    my_ip: ToolDefinition;
    whois: ToolDefinition;
}
/** Build all seven tool definitions from the resolved config. */
export declare function buildNetdoctorTools(config: ResolvedConfig): ToolSet;
//# sourceMappingURL=tools.d.ts.map