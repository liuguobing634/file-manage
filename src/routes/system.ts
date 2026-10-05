import { readVersion, SERVICE_NAME } from '../version.js';
import { Router } from 'express';
import type { AppContext } from '../context.js';
import { requireAuth } from '../middleware/auth.js';
import { collectRootProblems, processIdentity } from '../services/diagnostics.js';
import { asyncHandler } from '../utils/http.js';

export function createSystemRouter(ctx: AppContext): Router {
  const router = Router();

  router.get(
    '/info',
    requireAuth(ctx.tokens),
    asyncHandler(async (_req, res) => {
      const totp = await ctx.totp.status();
      const roots = await ctx.guard.rootsInfo();
      res.json({
        name: SERVICE_NAME,
        version: readVersion(),
        node: process.version,
        platform: process.platform,
        pid: process.pid,
        // 容器里排查「目录不可读」时最先要看的两个信息：进程身份 + 目录属主/权限
        process: processIdentity(),
        dataDir: ctx.config.dataDir,
        uptimeSeconds: Math.floor((Date.now() - ctx.startedAt) / 1000),
        processUptimeSeconds: Math.floor(process.uptime()),
        serverTime: new Date().toISOString(),
        allowedRoots: ctx.guard.allowedRoots,
        skippedRoots: ctx.config.skippedRoots,
        roots,
        rootProblems: collectRootProblems(roots),
        limits: {
          maxListFiles: ctx.config.maxListFiles,
          maxListDepth: ctx.config.maxListDepth,
          maxDeletePaths: ctx.config.maxDeletePaths,
          maxZipFiles: ctx.config.maxZipFiles,
        },
        totp: { configured: totp.configured, enabled: totp.enabled },
      });
    }),
  );

  return router;
}
