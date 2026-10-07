import * as api from '../adminApi'
import { AdminApiError, type AdminClient } from '../adminApi'
import { getAdminToken, setAdminToken, XrpcError } from '../xrpc'
import { isUnsupported } from './live'

// The console's way into lib/adminApi.ts. `withAdmin` hands a call the admin token and turns its
// errors into XrpcErrors, so a 401 sends the console back to the token form and the rest of the
// console's error handling applies. The `optional` wrappers are for the methods older vlpds builds
// don't have: they answer { supported: false } instead of throwing, so a page can show a
// "needs a newer vlpds" placeholder.

export type Optional<T> = { supported: true; data: T } | { supported: false; nsid: string }

export async function withAdmin<T>(run: (c: AdminClient) => Promise<T>): Promise<T> {
  const token = getAdminToken()
  if (!token) throw new XrpcError(401, 'AuthenticationRequired', 'Enter the admin token')
  try {
    return await run({ token })
  } catch (e) {
    if (e instanceof AdminApiError) {
      if (e.status === 401) setAdminToken(null)
      throw new XrpcError(e.status, e.error, e.message)
    }
    throw e
  }
}

async function optional<T>(nsid: string, run: (c: AdminClient) => Promise<T>): Promise<Optional<T>> {
  try {
    return { supported: true, data: await withAdmin(run) }
  } catch (e) {
    if (isUnsupported(e)) return { supported: false, nsid }
    throw e
  }
}

export type { MetricsPoint, NodeMetrics, Segment, NodeSegments, MailEntry, MailStatus, Lockout, NodeConfig, Setting } from '../adminApi'

/** Every node's last 3 minutes of rates (or those after `since`), gathered by the node serving the console. */
export const nodeMetrics = (since?: number) => optional('vlpds.admin.getNodeMetrics', (c) => api.getNodeMetrics(c, since))

/** Each node's recent log segments: when each was sealed and when its PUT was durable. */
export const segmentFeed = (since?: number) => optional('vlpds.admin.listSegments', (c) => api.listSegments(c, since))

/** Accounts whose second factor or email codes are locked after wrong codes. */
export const lockouts = () => optional('vlpds.admin.listLockouts', async (c) => (await api.listLockouts(c)).lockouts)

export const mailLog = (limit = 100) => optional('vlpds.admin.listMail', (c) => api.listMail(c, limit))

/** One node's settings; `node` relays the call to it. */
export const getConfig = (node?: string) => optional('vlpds.admin.getConfig', (c) => api.getConfig(c, node))

export const kickSubscriber = (node: string, conn: string) => optional('vlpds.admin.kickSubscriber', (c) => api.kickSubscriber(c, { node, conn }))
