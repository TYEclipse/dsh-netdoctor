/**
 * TLS certificate probe: performs a real handshake with node:tls and reports
 * protocol, cipher, and the leaf certificate's identity and validity window.
 * Certificates are inspected but never trusted (rejectUnauthorized: false),
 * so self-signed and expired certificates can still be diagnosed.
 *
 * @module dsh-netdoctor/tls
 */
import { connect } from 'node:tls';
import { isIP } from 'node:net';
import { assertValidPort, assertValidTarget, round2 } from "./util.js";
/** Compute whole days from `now` until `validTo` (negative = already expired). */
export function computeDaysRemaining(validTo, now) {
    const expiry = Date.parse(validTo);
    if (Number.isNaN(expiry))
        return 0;
    return round2((expiry - now) / 86_400_000);
}
/** Check the TLS certificate presented by host:port. */
export async function checkTls(hostInput, portInput, timeoutMs) {
    const host = assertValidTarget(hostInput);
    const port = assertValidPort(portInput);
    if (typeof timeoutMs !== 'number' || timeoutMs < 100 || timeoutMs > 60_000) {
        throw new Error('timeoutMs must be a number between 100 and 60000');
    }
    return new Promise((resolve) => {
        let settled = false;
        const socket = connect({
            host,
            port,
            // Node ≥20 throws ERR_TLS_SNI when SNI is set to an IP literal
            // ("Setting the TLS ServerName to an IP address is not permitted").
            // For IP targets we let Node omit SNI automatically (RFC 6066 — no SNI for IPs).
            ...(isIP(host) ? {} : { servername: host }),
            rejectUnauthorized: false,
            timeout: timeoutMs,
        });
        const finish = (result) => {
            if (settled)
                return;
            settled = true;
            socket.destroy();
            resolve({ host, port, ...result });
        };
        socket.setTimeout(timeoutMs, () => {
            finish({ connected: false, protocol: undefined, cipher: undefined, authorized: undefined, authorizationError: undefined, cert: undefined, detail: `handshake did not complete within ${timeoutMs} ms` });
        });
        socket.once('secureConnect', () => {
            const cert = socket.getPeerCertificate();
            const authorized = socket.authorized;
            const authorizationError = socket.authorizationError instanceof Error ? socket.authorizationError.message : String(socket.authorizationError ?? '');
            let certificate;
            if (cert !== null && typeof cert === 'object' && Object.keys(cert).length > 0) {
                const validFrom = String(cert.valid_from ?? '');
                const validTo = String(cert.valid_to ?? '');
                certificate = {
                    subject: String(cert.subject?.CN ?? ''),
                    issuer: String(cert.issuer?.CN ?? ''),
                    validFrom,
                    validTo,
                    daysRemaining: validTo === '' ? 0 : computeDaysRemaining(validTo, Date.now()),
                    altNames: typeof cert.subjectaltname === 'string' && cert.subjectaltname !== ''
                        ? cert.subjectaltname.split(',').map((entry) => entry.trim())
                        : [],
                    serialNumber: String(cert.serialNumber ?? ''),
                    fingerprint256: String(cert.fingerprint256 ?? ''),
                };
            }
            else {
                certificate = undefined;
            }
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();
            finish({
                connected: true,
                protocol: protocol ?? undefined,
                cipher: cipher !== null && cipher.name !== undefined ? `${cipher.name} ${String(cipher.version ?? '')}`.trim() : undefined,
                authorized,
                authorizationError: authorizationError === '' ? undefined : authorizationError,
                cert: certificate,
                detail: undefined,
            });
        });
        socket.once('error', (error) => {
            const code = error.code ?? '';
            if (code === 'ECONNREFUSED') {
                finish({ connected: false, protocol: undefined, cipher: undefined, authorized: undefined, authorizationError: undefined, cert: undefined, detail: `connection refused on port ${port}` });
            }
            else if (code === 'ECONNRESET') {
                finish({ connected: false, protocol: undefined, cipher: undefined, authorized: undefined, authorizationError: undefined, cert: undefined, detail: 'connection reset during the TLS handshake (server may not speak TLS on this port)' });
            }
            else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
                finish({ connected: false, protocol: undefined, cipher: undefined, authorized: undefined, authorizationError: undefined, cert: undefined, detail: `host lookup failed: ${error.message}` });
            }
            else {
                finish({ connected: false, protocol: undefined, cipher: undefined, authorized: undefined, authorizationError: undefined, cert: undefined, detail: error.message });
            }
        });
    });
}
//# sourceMappingURL=tls.js.map