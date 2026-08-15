/**
 * TLS certificate probe: performs a real handshake with node:tls and reports
 * protocol, cipher, and the leaf certificate's identity and validity window.
 * Certificates are inspected but never trusted (rejectUnauthorized: false),
 * so self-signed and expired certificates can still be diagnosed.
 *
 * @module dsh-netdoctor/tls
 */
export type TlsResult = {
    host: string;
    port: number;
    connected: boolean;
    protocol: string | undefined;
    cipher: string | undefined;
    authorized: boolean | undefined;
    authorizationError: string | undefined;
    cert: {
        subject: string;
        issuer: string;
        validFrom: string;
        validTo: string;
        daysRemaining: number;
        altNames: string[];
        serialNumber: string;
        fingerprint256: string;
    } | undefined;
    detail: string | undefined;
};
/** Compute whole days from `now` until `validTo` (negative = already expired). */
export declare function computeDaysRemaining(validTo: string, now: number): number;
/** Check the TLS certificate presented by host:port. */
export declare function checkTls(hostInput: string, portInput: number, timeoutMs: number): Promise<TlsResult>;
//# sourceMappingURL=tls.d.ts.map