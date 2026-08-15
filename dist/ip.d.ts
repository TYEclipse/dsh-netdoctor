/**
 * Public IP + geo probe. Uses ip-api.com's free keyless endpoint for the geo
 * part with a plain-IP fallback; both requests carry a hard timeout and are
 * plain GETs with no credentials.
 *
 * @module dsh-netdoctor/ip
 */
export type IpGeoResult = {
    ip: string;
    geo: {
        country: string;
        region: string;
        city: string;
        isp: string;
        org: string;
        as: string;
        timezone: string;
        lat: number;
        lon: number;
    } | undefined;
    geoNote: string | undefined;
};
/** Fetch this machine's public IP, optionally enriched with geo info. */
export declare function getPublicIp(includeGeo: boolean, timeoutMs: number): Promise<IpGeoResult>;
//# sourceMappingURL=ip.d.ts.map