// Entra sign-in for the HeatMap 360 results pages: auth code + PKCE with a server-side confidential client whose client
// assertion is a managed-identity token (federated identity credential), the same pattern as r360. No secret,
// certificate or key. Tokens stay in server memory.
//
// "Elevated" = an ACTIVE member of the HeatMap PIM group (HM360_ADMIN_GROUP_ID). "Settings Admin" = an ACTIVE member
// of the Settings Admin PIM group (HM360_PROJECT_ADMIN_GROUP_ID); only they may change settings such as where the
// findings table lives. PIM for Groups only adds the
// membership while the activation lasts, so the server re-checks it with Graph (/me/transitiveMemberOf, User.Read
// only) at most every 5 minutes and drops access as soon as the activation ends.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { ConfidentialClientApplication, CryptoProvider } from '@azure/msal-node';
import { FIC_AUDIENCE } from './identity.mjs';

export const SCOPES = ['https://graph.microsoft.com/User.Read'];
export const SESSION_COOKIE = '__Host-hm360';
export const SESSION_TTL = 8 * 60 * 60 * 1000;
export const PENDING_TTL = 10 * 60 * 1000;
export const ELEVATION_RECHECK = 5 * 60 * 1000;
export const PIM_GROUPS_URL = 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/ActivationMenuBlade/~/aadgroup';

export function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* ignore bad cookie */ } }
  }
  return out;
}

export class SessionStore {
  constructor({ now = () => Date.now(), ttl = SESSION_TTL, max = 1000 } = {}) { this.now = now; this.ttl = ttl; this.max = max; this.map = new Map(); }
  create() {
    if (this.map.size >= this.max) this.sweep();
    const s = { id: randomBytes(32).toString('base64url'), created: this.now(), csrf: randomBytes(32).toString('base64url'), user: null, elevation: null, projectElevation: null };
    this.map.set(s.id, s);
    return s;
  }
  get(id) {
    const s = id && this.map.get(id);
    if (!s) return null;
    if (this.now() - s.created > this.ttl) { this.map.delete(id); return null; }
    return s;
  }
  destroy(id) { this.map.delete(id); }
  sweep() { for (const [id, s] of this.map) if (this.now() - s.created > this.ttl) this.map.delete(id); if (this.map.size >= this.max) this.map.delete(this.map.keys().next().value); }
}

export const cookieHeader = (id, maxAgeSec) => `${SESSION_COOKIE}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}`;

export function checkCallback(pending, query, now = Date.now()) {
  if (!pending) return 'No sign-in is in progress. Start again.';
  if (now - pending.created > PENDING_TTL) return 'The sign-in expired. Start again.';
  if (query.error) return 'Microsoft did not complete the sign-in.';
  if (typeof query.state !== 'string' || query.state !== pending.state) return 'The sign-in response did not match this browser session.';
  if (typeof query.code !== 'string' || query.code.length < 10) return 'The sign-in response had no authorization code.';
  return null;
}

export function userFromClaims(claims, { tenantId, clientId }) {
  if (!claims || claims.tid !== tenantId) throw new Error('Wrong tenant');
  if (claims.aud && claims.aud !== clientId) throw new Error('Wrong audience');
  if (!/^[0-9a-f-]{36}$/i.test(claims.oid || '')) throw new Error('No object id');
  return { oid: claims.oid.toLowerCase(), upn: claims.preferred_username || '', name: claims.name || claims.preferred_username || '' };
}

const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Is the signed-in user an active (transitive) member of the group? Pure HTTP; `fetchImpl` is swapped in tests.
export async function isActiveMember(accessToken, groupId, fetchImpl = (...a) => fetch(...a), setting = 'HM360_ADMIN_GROUP_ID') {
  if (!/^[0-9a-f-]{36}$/i.test(groupId || '')) throw new Error(`${setting} is not a group object id`);
  const url = `https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$count=true&$select=id&$filter=id eq '${groupId}'`;
  const r = await fetchImpl(url, { headers: { authorization: `Bearer ${accessToken}`, consistencylevel: 'eventual' }, redirect: 'error', signal: AbortSignal.timeout(15_000) });
  if (!r.ok) throw new Error(`Graph membership check failed: HTTP ${r.status}`);
  const data = await r.json();
  return (data.value || []).some(g => String(g.id).toLowerCase() === groupId.toLowerCase());
}

export function createAuth({ config, miToken, msal = {}, fetchImpl }) {
  const cca = new ConfidentialClientApplication({
    auth: { clientId: config.clientId, authority: msal.authority || `https://login.microsoftonline.com/${config.tenantId}`, clientAssertion: async () => miToken(FIC_AUDIENCE), ...(msal.auth || {}) },
    system: { loggerOptions: { piiLoggingEnabled: false, logLevel: 0, loggerCallback: () => {} }, ...(msal.system || {}) },
  });
  const crypto = new CryptoProvider();
  const token = async session => {
    const account = await cca.getTokenCache().getAccountByHomeId(session.homeAccountId);
    if (!account) throw Object.assign(new Error('Session expired. Sign in again.'), { status: 401 });
    try { return (await cca.acquireTokenSilent({ account, scopes: SCOPES })).accessToken; }
    catch { throw Object.assign(new Error('Session expired. Sign in again.'), { status: 401 }); }
  };
  return {
    async beginSignIn(session) {
      const { verifier, challenge } = await crypto.generatePkceCodes();
      session.pending = { state: randomBytes(24).toString('hex'), nonce: randomBytes(24).toString('hex'), verifier, created: Date.now() };
      return cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: config.redirectUri, codeChallenge: challenge, codeChallengeMethod: 'S256',
        state: session.pending.state, nonce: session.pending.nonce, prompt: 'select_account' });
    },
    async completeSignIn(session, query) {
      const pending = session.pending;
      session.pending = null;
      const problem = checkCallback(pending, query);
      if (problem) throw Object.assign(new Error(problem), { status: 400 });
      const result = await cca.acquireTokenByCode(
        { code: query.code, scopes: SCOPES, redirectUri: config.redirectUri, codeVerifier: pending.verifier, state: query.state, nonce: pending.nonce },
        { code: query.code, state: query.state, nonce: pending.nonce });
      if (!safeEq(result.idTokenClaims?.nonce, pending.nonce)) throw Object.assign(new Error('The sign-in response did not match this browser session.'), { status: 400 });
      session.user = userFromClaims(result.idTokenClaims, { tenantId: config.tenantId, clientId: config.clientId });
      session.homeAccountId = result.account.homeAccountId;
      session.elevation = null;
      session.projectElevation = null;
      return session.user;
    },
    // Cached for ELEVATION_RECHECK unless `force` (the "I activated it, check again" button).
    async elevated(session, { force = false, now = Date.now() } = {}) {
      if (!session.user) return false;
      if (!force && session.elevation && now - session.elevation.at < ELEVATION_RECHECK) return session.elevation.ok;
      const ok = await isActiveMember(await token(session), config.adminGroupId, fetchImpl);
      session.elevation = { ok, at: now };
      return ok;
    },
    // Same check for the Settings Admin group. Not configured = nobody is a Settings Admin.
    async projectAdmin(session, { force = false, now = Date.now() } = {}) {
      if (!session.user || !config.projectAdminGroupId) return false;
      if (!force && session.projectElevation && now - session.projectElevation.at < ELEVATION_RECHECK) return session.projectElevation.ok;
      const ok = await isActiveMember(await token(session), config.projectAdminGroupId, fetchImpl, 'HM360_PROJECT_ADMIN_GROUP_ID');
      session.projectElevation = { ok, at: now };
      return ok;
    },
    async signOut(session) {
      const account = session.homeAccountId && await cca.getTokenCache().getAccountByHomeId(session.homeAccountId);
      if (account) await cca.getTokenCache().removeAccount(account);
    },
  };
}
