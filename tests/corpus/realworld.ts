// Labeled precision corpus — patterns sourced from the real-world validation
// run against fastify, flask, and OWASP Juice Shop (docs/dev/REALWORLD.md).
// Every unannotated line here was a live Stage 1 false positive before the
// CG-060 / CG-003 / CG-001 gates were tightened; the ratchet keeps them fixed.

import express from 'express';
const app = express();

// ── CG-060: incoming request objects are not HTTP clients ──────────────────

export function logIncoming(request: any, reply: any) {
  // fastify hands every handler an incoming `request`; logging on it is
  // not an outgoing HTTP call.
  request.log.info({ req: request }, 'incoming request');
  request.log.warn('route not found');
  request.server.emit('requestLogged', reply);
}

export function registerHooks(resource: any) {
  // Hook registration on a property chain that merely contains "fetch".
  resource.list.fetch.after((req: any, res: any, context: any) => context.continue);
}

// ── CG-003: timers with function arguments are not eval ────────────────────

export function pollForever(poll: () => void, ms: number) {
  setTimeout(poll, ms);
  setInterval(() => { poll(); }, ms);
}

export function configureServer(server: any, options: any) {
  // Socket-timeout API, not the eval-family global.
  server.setTimeout(options.connectionTimeout);
}

// ── CG-001: literal SQL is a constant, however many keywords it holds ───────

export async function listTables(db: any) {
  return db.query('SELECT sql FROM sqlite_master');
}

export async function activeUsers(db: any) {
  return db.query(`SELECT id, name
    FROM users
    WHERE active = 1`);
}

// ── The same call shapes with genuinely dynamic input must still fire ──────

app.get('/proxy', async (req: any, res: any) => {
  const upstream = await fetch(`http://internal/${req.params.host}`); // codeguard-expect CG-060
  res.json(await upstream.json());
});

export function legacyRefresh(action: string) {
  setTimeout('refresh_' + action + '()', 1000); // codeguard-expect CG-003
}
