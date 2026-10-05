import type { Request, RequestHandler } from 'express';
import { AppError, ErrorCodes } from '../errors.js';
import type { TokenService } from '../services/tokens.js';

export interface RequireAuthOptions {
  /** 是否允许通过 ?token= 传递（仅下载 / 二维码这类浏览器直连场景） */
  allowQueryToken?: boolean;
}

export function extractToken(req: Request, allowQueryToken: boolean): string | undefined {
  const header = req.get('authorization');
  if (header) {
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    if (match?.[1]) return match[1].trim();
  }
  const custom = req.get('x-auth-token');
  if (custom && custom.trim() !== '') return custom.trim();
  if (allowQueryToken) {
    const raw = req.query['token'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return undefined;
}

export function requireAuth(tokens: TokenService, options: RequireAuthOptions = {}): RequestHandler {
  const allowQueryToken = options.allowQueryToken ?? false;
  return (req, _res, next) => {
    const token = extractToken(req, allowQueryToken);
    if (!token) {
      next(
        AppError.unauthorized(
          ErrorCodes.TOKEN_MISSING,
          '缺少访问令牌，请在请求头携带 Authorization: Bearer <token>（或 X-Auth-Token）',
        ),
      );
      return;
    }
    try {
      req.auth = tokens.verify(token);
      next();
    } catch (error) {
      next(error);
    }
  };
}
