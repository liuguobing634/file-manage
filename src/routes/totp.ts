import { Router } from 'express';
import type { AppContext } from '../context.js';
import { ErrorCodes, isAppError } from '../errors.js';
import { requireAuth } from '../middleware/auth.js';
import { RateLimiter, ipUserKey, rateLimitMiddleware } from '../middleware/rateLimit.js';
import { asyncHandler, clientIp } from '../utils/http.js';
import { asObject, reqPattern } from '../utils/validate.js';

export function createTotpRouter(ctx: AppContext): Router {
  const router = Router();
  const auth = requireAuth(ctx.tokens);
  // 二维码需要能被 <img src> 直接引用，因此允许 ?token= 传递
  const authForImage = requireAuth(ctx.tokens, { allowQueryToken: true });
  const limiter = new RateLimiter({
    ...ctx.config.totpRate,
    message: '二次验证尝试过于频繁，请稍后再试',
  });

  router.get(
    '/status',
    auth,
    asyncHandler(async (_req, res) => {
      res.json(await ctx.totp.status());
    }),
  );

  router.post(
    '/setup',
    auth,
    asyncHandler(async (req, res) => {
      const result = await ctx.totp.setup();
      ctx.audit.record({
        action: 'totp_setup',
        result: 'success',
        username: req.auth?.username,
        ip: clientIp(req),
        requestId: req.requestId,
        detail: { createdAt: result.createdAt, issuer: result.issuer, account: result.account },
      });
      res.json(result);
    }),
  );

  router.get(
    '/qrcode',
    authForImage,
    asyncHandler(async (_req, res) => {
      const { buffer } = await ctx.totp.qrCodePng();
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Cache-Control', 'no-store');
      res.send(buffer);
    }),
  );

  router.post(
    '/verify',
    auth,
    rateLimitMiddleware(limiter, ipUserKey, '二次验证尝试过于频繁，请稍后再试'),
    asyncHandler(async (req, res) => {
      const body = asObject(req.body ?? {});
      const code = reqPattern(body, 'code', /^\d{4,10}$/, '必须是数字验证码');
      const key = ipUserKey(req);
      try {
        const result = await ctx.totp.activate(code);
        limiter.reset(key);
        ctx.audit.record({
          action: 'totp_activate',
          result: 'success',
          username: req.auth?.username,
          ip: clientIp(req),
          requestId: req.requestId,
          detail: { enabledAt: result.enabledAt },
        });
        res.json({ enabled: true, enabledAt: result.enabledAt });
      } catch (error) {
        if (isAppError(error) && error.code === ErrorCodes.TOTP_INVALID) {
          limiter.record(key);
          ctx.audit.record({
            action: 'totp_failed',
            result: 'failure',
            username: req.auth?.username,
            ip: clientIp(req),
            requestId: req.requestId,
            detail: { scene: 'activate' },
          });
        }
        throw error;
      }
    }),
  );

  return router;
}
