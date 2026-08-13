/**
 * Public IP + geo probe. Uses ip-api.com's free keyless endpoint for the geo
 * part with a plain-IP fallback; both requests carry a hard timeout and are
 * plain GETs with no credentials.
 *
 * @module dsh-netdoctor/ip
 */

export type IpGeoResult = {
  ip: string
  geo: {
    country: string
    region: string
    city: string
    isp: string
    org: string
    as: string
    timezone: string
    lat: number
    lon: number
  } | undefined
  geoNote: string | undefined
}

/** HTTP GET with a hard timeout; returns the body or throws. */
async function httpGet(url: string, timeoutMs: number): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, { signal: controller.signal, headers: { 'user-agent': 'dsh-netdoctor/0.1' } })
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`)
    }
    return await response.text()
  } finally {
    clearTimeout(timer)
  }
}

interface IpApiPayload {
  status?: string
  query?: string
  country?: string
  regionName?: string
  city?: string
  isp?: string
  org?: string
  as?: string
  timezone?: string
  lat?: number
  lon?: number
}

/** Fetch this machine's public IP, optionally enriched with geo info. */
export async function getPublicIp(includeGeo: boolean, timeoutMs: number): Promise<IpGeoResult> {
  if (typeof timeoutMs !== 'number' || timeoutMs < 1000 || timeoutMs > 60_000) {
    throw new Error('httpTimeoutMs must be a number between 1000 and 60000')
  }

  let ip: string | undefined
  let geo: IpGeoResult['geo']
  let geoNote: string | undefined

  if (includeGeo) {
    try {
      const body = await httpGet(
        'http://ip-api.com/json?fields=status,query,country,regionName,city,isp,org,as,timezone,lat,lon',
        timeoutMs,
      )
      const payload = JSON.parse(body) as IpApiPayload
      if (payload.status === 'success' && payload.query !== undefined) {
        ip = payload.query
        geo = {
          country: payload.country ?? '',
          region: payload.regionName ?? '',
          city: payload.city ?? '',
          isp: payload.isp ?? '',
          org: payload.org ?? '',
          as: payload.as ?? '',
          timezone: payload.timezone ?? '',
          lat: payload.lat ?? 0,
          lon: payload.lon ?? 0,
        }
      } else {
        geoNote = `geo lookup unavailable (ip-api.com answered status "${payload.status ?? 'unknown'}"); falling back to plain IP`
      }
    } catch (error) {
      geoNote = `geo lookup failed (${error instanceof Error ? error.message : String(error)}); falling back to plain IP`
    }
  }

  if (ip === undefined) {
    try {
      ip = (await httpGet('https://api.ipify.org', timeoutMs)).trim()
    } catch (error) {
      throw new Error(`could not determine public IP (ipify fallback failed: ${error instanceof Error ? error.message : String(error)})`)
    }
  }

  return { ip, geo, geoNote }
}
