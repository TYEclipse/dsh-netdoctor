/**
 * ICMP ping probe: delegates to the platform's ping utility (fixed argument
 * arrays, never a shell) and parses the human-readable summary.
 *
 * @module dsh-netdoctor/ping
 */
export type PingResult = {
    host: string;
    resolvedAddress: string | undefined;
    transmitted: number;
    received: number;
    lossPercent: number;
    rttMs: {
        min: number;
        avg: number;
        max: number;
    } | undefined;
    note: string | undefined;
    raw: string;
};
/** Build the platform-specific argument array for the ping binary. */
export declare function pingArgs(host: string, count: number, timeoutSec: number): string[];
/** Parse the resolved address from a "PING host (1.2.3.4) ..." banner line. */
export declare function parseResolvedAddress(text: string): string | undefined;
/** Ping a host `count` times and summarize the result. */
export declare function pingHost(hostInput: string, count: number, timeoutSec: number): Promise<PingResult>;
//# sourceMappingURL=ping.d.ts.map