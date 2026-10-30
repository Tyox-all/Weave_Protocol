#!/usr/bin/env node
/**
 * Weave Protocol API server: fail-closed bind check, then listen.
 */
import app, { PORT, HOST, API_KEY, LOOPBACK, CORS_ORIGINS, DEMO } from './app.js';

if (!API_KEY && !LOOPBACK && process.env.WEAVE_ALLOW_UNAUTHENTICATED !== '1') {
  console.error(`Refusing to listen on ${HOST} without WEAVE_API_KEY. Set a key, bind to 127.0.0.1, or set WEAVE_ALLOW_UNAUTHENTICATED=1 if this is intentional.`);
  process.exit(1);
}

app.listen(PORT, HOST, () => {
  console.log(`🕸️  Weave Protocol API v1.2.0 on http://${HOST}:${PORT}  (dashboard: /dashboard)`);
  console.log(`   auth: ${API_KEY ? 'API key required' : 'OFF (local only)'} · CORS: ${CORS_ORIGINS.length ? CORS_ORIGINS.join(', ') : 'same-origin only'} · demo endpoints: ${DEMO ? 'ON' : 'off'}`);
});
