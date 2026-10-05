import { Router } from 'express';
import type { AppContext } from '../context.js';
import { AppError, ErrorCodes } from '../errors.js';
import { requireAuth } from '../middleware/auth.js';
import { RateLimiter, rateLimitMiddleware } from '../middleware/rateLimit.js';
import { safeEqualString, verifyPassword } from '../services/passwords.js';
import { asyncHandler, clientIp } from '../utils/http.js';
import { asObject, coerceScalar, reqString } from '../utils/validate.js';

export function createAuthRouter(ctx: AppContext): Router {
  const router = Router();
  const limiter = new RateLimiter({
    ...ctx.config.loginRate,
    message: '登录尝试过于频繁，请稍后再试',
  });

  const loginKey = (req: { body?: unknown; ip?: string; socket?: { remoteAddress?: string } }): string => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = (coerceScalar(body['username']) ?? '-').toLowerCase();
    const ip = (req as { ip?: string }).ip ?? req.socket?.remoteAddress ?? 'unknown';
    return `${ip}|${username}`;
  };

  router.post(
    '/login',
    rateLimitMiddleware(limiter, (req) => loginKey(req), '登录尝试过于频繁，请稍后再试'),
    asyncHandler(async (req, res) => {
      const body = asObject(req.body ?? {});
      const username = reqString(body, 'username', { maxLength: 128 });
      const password = reqString(body, 'password', { maxLength: 512 });
      const ip = clientIp(req);
      const key = `${ip}|${username.toLowerCase()}`;

      // 两个判断都执行，避免通过响应时间区分「账号不存在」与「密码错误」
      const passwordOk = await verifyPassword(password, ctx.credentials);
      const usernameOk = safeEqualString(username, ctx.config.adminUsername);

      if (!passwordOk || !usernameOk) {
        limiter.record(key);
        const state = limiter.check(key);
        ctx.audit.record({
          action: 'login_failed',
          result: 'failure',
          username,
          ip,
          requestId: req.requestId,
          detail: { attemptsInWindow: state.hits },
        });
        throw AppError.unauthorized(ErrorCodes.INVALID_CREDENTIALS, '账号或密码错误');
      }

      limiter.reset(key);
      const issued = ctx.tokens.issue(ctx.config.adminUsername);
      ctx.audit.record({
        action: 'login',
        result: 'success',
        username: ctx.config.adminUsername,
        ip,
        requestId: req.requestId,
        detail: { expiresAt: issued.expiresAt },
      });
      res.json({
        token: issued.token,
        tokenType: 'Bearer',
        expiresIn: issued.expiresIn,
        username: ctx.config.adminUsername,
        expiresAt: issued.expiresAt,
      });
    }),
  );

  router.get(
    '/me',
    requireAuth(ctx.tokens),
    asyncHandler(async (req, res) => {
      const auth = req.auth!;
      const totp = await ctx.totp.status();
      res.json({
        username: auth.username,
        issuedAt: new Date(auth.issuedAt).toISOString(),
        expiresAt: new Date(auth.expiresAt).toISOString(),
        totp: { configured: totp.configured, enabled: totp.enabled },
      });
    }),
  );

  router.post(
    '/logout',
    requireAuth(ctx.tokens),
    asyncHandler(async (req, res) => {
      const auth = req.auth!;
      ctx.tokens.revoke(auth);
      ctx.audit.record({
        action: 'logout',
        result: 'success',
        username: auth.username,
        ip: clientIp(req),
        requestId: req.requestId,
      });
      res.json({ ok: true });
    }),
  );

  return router;
}
