// All settings come from the environment (Container Apps env vars and secret refs). Nothing secret is in git.
import path from 'node:path';

export function loadConfig(env = process.env, root = process.cwd()) {
  const publicUrl = (env.HM360_PUBLIC_URL || `http://localhost:${env.PORT || 3460}`).replace(/\/$/, '');
  const [owner, repo] = String(env.HM360_DATA_REPO || '').split('/');
  return {
    port: Number(env.PORT || 3460),
    bind: env.HM360_BIND || '127.0.0.1',
    publicUrl,
    production: env.NODE_ENV === 'production',
    data: owner && repo
      ? { kind: 'github', owner, repo, branch: env.HM360_DATA_BRANCH || 'main', token: env.HM360_GITHUB_TOKEN || '' }
      : { kind: 'local', dir: path.resolve(env.HM360_DATA_DIR || path.join(root, 'data', 'exchange')) },
    entra: env.HM360_TENANT_ID && env.HM360_CLIENT_ID ? {
      tenantId: env.HM360_TENANT_ID, clientId: env.HM360_CLIENT_ID, miClientId: env.HM360_MI_CLIENT_ID || '',
      adminGroupId: env.HM360_ADMIN_GROUP_ID || '', projectAdminGroupId: env.HM360_PROJECT_ADMIN_GROUP_ID || '', redirectUri: env.HM360_REDIRECT_URI || `${publicUrl}/auth/callback`,
    } : null,
    // Local development only: treat the browser as an elevated admin. Refused in production and when Entra or the GitHub
    // data repo is configured. Needs a 127.0.0.1 bind, or HM360_DEV_ADMIN_CONTAINER=1 inside a local container whose
    // port is published on the host's loopback only (compose.yaml does this).
    devAdmin: env.HM360_DEV_ADMIN === '1' && env.NODE_ENV !== 'production'
      && !(env.HM360_TENANT_ID && env.HM360_CLIENT_ID) && !env.HM360_DATA_REPO
      && ((env.HM360_BIND || '127.0.0.1') === '127.0.0.1' || env.HM360_DEV_ADMIN_CONTAINER === '1'),
    limits: { perIp10Min: Number(env.HM360_UPLOADS_PER_10MIN || 5), perIpDay: Number(env.HM360_UPLOADS_PER_DAY || 20), globalDay: Number(env.HM360_UPLOADS_GLOBAL_DAY || 500) },
  };
}
