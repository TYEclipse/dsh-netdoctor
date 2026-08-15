/**
 * Shared helpers for dsh-netdoctor probes: target validation, process
 * execution with timeouts, and result normalizers.
 *
 * All external binaries are invoked with fixed argument arrays (never through
 * a shell), so no user input can reach a shell interpreter.
 *
 * @module dsh-netdoctor/util
 */
/** Validate a probe target (hostname, IPv4 or IPv6). Throws with a clear message on garbage input. */
export declare function assertValidTarget(input: string, what?: string): string;
/** Validate a TCP port. */
export declare function assertValidPort(port: unknown): number;
/** Result of running an external probe binary. */
export interface ProcessResult {
    code: number | null;
    stdout: string;
    stderr: string;
    timedOut: boolean;
    spawnError: string | undefined;
}
/** Spawn a fixed binary with a fixed argument array, capture output, enforce a timeout. */
export declare function runProcess(binary: string, args: string[], timeoutMs: number): Promise<ProcessResult>;
/** Extract the numeric min/avg/max figures from an rtt summary line (milliseconds, may be fractional). */
export declare function parseRttSummary(line: string): {
    min: number;
    avg: number;
    max: number;
} | undefined;
/** Parse "N packets transmitted, M received, X% packet loss" style summaries. */
export declare function parsePacketSummary(text: string): {
    transmitted: number;
    received: number;
    lossPercent: number;
} | undefined;
/** Round to two decimals for display. */
export declare function round2(value: number): number;
//# sourceMappingURL=util.d.ts.map