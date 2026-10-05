import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import express, { type Express } from 'express';
import type { AppContext } from './context.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { createAuthRouter } from './routes/auth.js';
import { createFilesRouter } from './routes/files.js';
import { createSystemRouter } from './routes/system.js';
import { createTotpRouter } from './routes/totp.js';
import { readVersion, SERVICE_NAME } from './version.js';

const CSP = [
  "default-src 'self'",
  "img-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function createApp(ctx: AppContext): Express {
  const app = express();
  app.disable('x-powered-by');
  if (ctx.config.trustProxy) app.set('trust proxy', true);

  app.use((req, res, next) => {
    const incoming = req.get('x-request-id');
    const id = incoming && /^[\w.:-]{1,128}$/.test(incoming) ? incoming : randomUUID();
    req.requestId = id;
    res.setHeader('X-Request-Id', id);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', CSP);
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  app.get('/healthz', (_req, res) => {
    res.json({
      status: 'ok',
      name: SERVICE_NAME,
      version: readVersion(),
      uptimeSeconds: Math.floor((Date.now() - ctx.startedAt) / 1000),
    });
  });

  app.use('/api/auth', createAuthRouter(ctx));
  app.use('/api/totp', createTotpRouter(ctx));
  app.use('/api', createFilesRouter(ctx));
  app.use('/api/system', createSystemRouter(ctx));

  if (ctx.config.serveStatic) {
    const publicDir = fileURLToPath(new URL('../public', import.meta.url));
    if (fs.existsSync(publicDir)) {
      app.use(
        express.static(publicDir, {
          index: 'index.html',
          etag: true,
          setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache'),
        }),
      );
    } else {
      ctx.logger.debug('未找到静态控制台目录，跳过', { publicDir });
    }
  }

  app.use(notFoundHandler());
  app.use(errorHandler(ctx.logger));
  return app;
}
