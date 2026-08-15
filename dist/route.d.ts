/**
 * Traceroute probe: delegates to the platform's traceroute utility (tracert on
 * Windows) and parses the hop list. Parsing is lenient — unparseable lines are
 * kept verbatim so the output is always useful.
 *
 * @module dsh-netdoctor/route
 */
export type TraceHop = {
    hop: number;
    host: string | undefined;
    address: string | undefined;
    rttsMs: number[];
    raw: string;
};
export type TraceResult = {
    host: string;
    maxHops: number;
    hops: TraceHop[];
    complete: boolean;
    note: string | undefined;
    raw: string;
};
/** Build the platform-specific argument array for the traceroute binary. */
export declare function traceArgs(host: string, maxHops: number, perHopTimeoutSec: number): {
    binary: string;
    args: string[];
};
/** Parse one traceroute output line into a hop (returns undefined for banners/headers). */
export declare function parseTraceLine(line: string): TraceHop | undefined;
/** Run a traceroute and parse the hop list. */
export declare function traceRoute(hostInput: string, maxHops: number, perHopTimeoutSec: number): Promise<TraceResult>;
//# sourceMappingURL=route.d.ts.map