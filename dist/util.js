/**
 * Shared helpers for dsh-netdoctor probes: target validation, process
 * execution with timeouts, and result normalizers.
 *
 * All external binaries are invoked with fixed argument arrays (never through
 * a shell), so no user input can reach a shell interpreter.
 *
 * @module dsh-netdoctor/util
 */
import { spawn } from 'node:child_process';
/** A hostname label or an IPv4/IPv6 literal. Rejects anything with whitespace or shell metacharacters. */
const HOSTNAME_RE = /^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;
/** Validate a probe target (hostname, IPv4 or IPv6). Throws with a clear message on garbage input. */
export function assertValidTarget(input, what = 'host') {
    const host = input.trim();
    if (host.length === 0 || host.length > 253) {
        throw new Error(`${what} must be a hostname or IP address (got empty or oversized input)`);
    }
    if (IPV4_RE.test(host)) {
        const octets = host.split('.').map(Number);
        if (octets.every((octet) => octet >= 0 && octet <= 255))
            return host;
        // Numeric quad with out-of-range octets: reject rather than pass to DNS.
        throw new Error(`${what} "${input}" looks like an IPv4 address with out-of-range octets`);
    }
    if (HOSTNAME_RE.test(host))
        return host;
    if (IPV6_RE.test(host) && host.includes(':'))
        return host;
    throw new Error(`${what} "${input}" is not a valid hostname or IP address`);
}
/** Validate a TCP port. */
export function assertValidPort(port) {
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`port must be an integer between 1 and 65535 (got ${String(port)})`);
    }
    return port;
}
/** Spawn a fixed binary with a fixed argument array, capture output, enforce a timeout. */
export function runProcess(binary, args, timeoutMs) {
    return new Promise((resolve) => {
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        let settled = false;
        let child;
        let exitCode = null;
        try {
            child = spawn(binary, args, { windowsHide: true });
        }
        catch (error) {
            resolve({
                code: null,
                stdout: '',
                stderr: '',
                timedOut: false,
                spawnError: error instanceof Error ? error.message : String(error),
            });
            return;
        }
        const finish = () => {
            if (settled)
                return;
            settled = true;
            resolve({ code: exitCode, stdout, stderr, timedOut, spawnError: undefined });
        };
        const timer = setTimeout(() => {
            timedOut = true;
            try {
                child.kill('SIGKILL');
            }
            catch {
                // already gone
            }
        }, timeoutMs);
        child.stdout?.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        child.stderr?.on('data', (chunk) => {
            stderr += chunk.toString();
        });
        child.on('error', (error) => {
            clearTimeout(timer);
            if (settled)
                return;
            settled = true;
            resolve({
                code: null,
                stdout,
                stderr,
                timedOut: false,
                spawnError: error.code === 'ENOENT'
                    ? `the "${binary}" utility is not installed on this system`
                    : error.message,
            });
        });
        child.on('close', (code) => {
            exitCode = code;
            clearTimeout(timer);
            finish();
        });
    });
}
/** Extract the numeric min/avg/max figures from an rtt summary line (milliseconds, may be fractional). */
export function parseRttSummary(line) {
    const match = /=\s*([\d.]+)\/([\d.]+)\/([\d.]+)(?:\/([\d.]+))?\s*ms/.exec(line);
    if (match === null)
        return undefined;
    return {
        min: Number(match[1]),
        avg: Number(match[2]),
        max: Number(match[3]),
    };
}
/** Parse "N packets transmitted, M received, X% packet loss" style summaries. */
export function parsePacketSummary(text) {
    const unix = /(\d+)\s+packets? transmitted,?\s+(\d+)\s+(?:packets? )?received,?\s+([\d.]+)%\s+packet loss/i.exec(text);
    if (unix !== null) {
        return {
            transmitted: Number(unix[1]),
            received: Number(unix[2]),
            lossPercent: Number(unix[3]),
        };
    }
    const win = /Packets:?\s*Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*(\d+)\s*\(([\d.]+)%\s*loss\)/is.exec(text);
    if (win !== null) {
        return {
            transmitted: Number(win[1]),
            received: Number(win[2]),
            lossPercent: Number(win[4]),
        };
    }
    return undefined;
}
/** Round to two decimals for display. */
export function round2(value) {
    return Math.round(value * 100) / 100;
}
//# sourceMappingURL=util.js.map