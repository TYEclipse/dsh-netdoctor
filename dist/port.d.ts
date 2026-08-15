/**
 * TCP port probe: attempts a raw TCP connect and classifies the outcome as
 * open / closed / filtered. Uses node:net — no external binaries.
 *
 * @module dsh-netdoctor/port
 */
export type PortStatus = 'open' | 'closed' | 'filtered' | 'unreachable';
export type PortResult = {
    host: string;
    port: number;
    status: PortStatus;
    connectMs: number | undefined;
    detail: string | undefined;
};
/** Try to open a TCP connection; classify the outcome. */
export declare function checkPort(hostInput: string, portInput: number, timeoutMs: number): Promise<PortResult>;
//# sourceMappingURL=port.d.ts.map