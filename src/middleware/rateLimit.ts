import type { Request, RequestHandler } from 'express';
import { AppError } from '../errors.js';
import { clientIp } from '../utils/http.js';

export interface RateLimiterOptions {
  windowSeconds: number;
  maxAttempts: number;
  message?: string;
}

export interface RateCheckResult {
  allowed: boolean;
  remaining: number;
  retryAfter: number;
  hits: number;
}

/**
 * 进程内滑动窗口限流器（无需 Redis，单实例部署足够）。
 * 只记录失败尝试，避免正常用户被自己的成功请求挤掉额度。
 */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly timer: NodeJS.Timeout;

  constructor(private readonly options: RateLimiterOptions) {
    this.timer = setInterval(() => this.prune(), Math.max(30_000, this.options.windowSeconds * 1000));
    this.timer.unref();
  }

  private windowStart(now: number): number {
    return now - this.options.windowSeconds * 1000;
  }

  check(key: string, now = Date.now()): RateCheckResult {
    const list = (this.hits.get(key) ?? []).filter((ts) => ts > this.windowStart(now));
    if (list.length === 0) this.hits.delete(key);
    else this.hits.set(key, list);
    const remaining = Math.max(0, this.options.maxAttempts - list.length);
    const allowed = list.length < this.options.maxAttempts;
    const retryAfter = allowed || list.length === 0 ? 0 : Math.ceil((list[0]! + this.options.windowSeconds * 1000 - now) / 1000);
    return { allowed, remaining, retryAfter, hits: list.length };
  }

  record(key: string, now = Date.now()): void {
    const list = (this.hits.get(key) ?? []).filter((ts) => ts > this.windowStart(now));
    list.push(now);
    this.hits.set(key, list);
  }

  reset(key?: string): void {
    if (key === undefined) this.hits.clear();
    else this.hits.delete(key);
  }

  dispose(): void {
    clearInterval(this.timer);
    this.hits.clear();
  }

  private prune(): void {
    const now = Date.now();
    for (const [key, list] of this.hits) {
      const kept = list.filter((ts) => ts > this.windowStart(now));
      if (kept.length === 0) this.hits.delete(key);
      else this.hits.set(key, kept);
    }
  }
}

/** 生成限流中间件：超出额度直接 429 + Retry-After */
export function rateLimitMiddleware(limiter: RateLimiter, keyFn: (req: Request) => string, message?: string): RequestHandler {
  return (req, _res, next) => {
    const result = limiter.check(keyFn(req));
    if (!result.allowed) {
      next(AppError.tooMany(message ?? '操作过于频繁，请稍后再试', result.retryAfter));
      return;
    }
    next();
  };
}

export function ipKey(req: Request): string {
  return clientIp(req);
}

export function ipUserKey(req: Request): string {
  return `${clientIp(req)}|${req.auth?.username ?? '-'}`;
}
