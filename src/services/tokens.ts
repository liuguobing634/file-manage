import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { AppError, ErrorCodes } from '../errors.js';

export interface AuthContext {
  username: string;
  jti: string;
  issuedAt: number;
  expiresAt: number;
}

export interface IssuedToken {
  token: string;
  jti: string;
  expiresIn: number;
  issuedAt: string;
  expiresAt: string;
}

interface PayloadShape extends jwt.JwtPayload {
  sub?: string;
  jti?: string;
}

const ISSUER = 'file-manage';

/**
 * JWT 签发与校验。注销采用内存 jti 黑名单（进程重启后失效，
 * 对短 TTL 的运维令牌足够；如需强一致请换成 Redis）。
 */
export class TokenService {
  private readonly revoked = new Map<string, number>();

  constructor(
    private readonly secret: string,
    private readonly ttlSeconds: number,
  ) {}

  issue(username: string): IssuedToken {
    const jti = randomUUID();
    const nowSeconds = Math.floor(Date.now() / 1000);
    const token = jwt.sign({ sub: username }, this.secret, {
      algorithm: 'HS256',
      issuer: ISSUER,
      jwtid: jti,
      expiresIn: this.ttlSeconds,
    });
    return {
      token,
      jti,
      expiresIn: this.ttlSeconds,
      issuedAt: new Date(nowSeconds * 1000).toISOString(),
      expiresAt: new Date((nowSeconds + this.ttlSeconds) * 1000).toISOString(),
    };
  }

  verify(token: string): AuthContext {
    let payload: PayloadShape;
    try {
      payload = jwt.verify(token, this.secret, { algorithms: ['HS256'], issuer: ISSUER }) as PayloadShape;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw AppError.unauthorized(ErrorCodes.TOKEN_INVALID, '登录状态已过期，请重新登录');
      }
      throw AppError.unauthorized(ErrorCodes.TOKEN_INVALID, '登录状态无效');
    }
    const username = payload.sub;
    const jti = payload.jti;
    if (typeof username !== 'string' || username === '' || typeof jti !== 'string' || jti === '') {
      throw AppError.unauthorized(ErrorCodes.TOKEN_INVALID, '登录状态无效');
    }
    this.prune();
    if (this.revoked.has(jti)) {
      throw AppError.unauthorized(ErrorCodes.TOKEN_REVOKED, '该登录状态已注销，请重新登录');
    }
    return {
      username,
      jti,
      issuedAt: (payload.iat ?? 0) * 1000,
      expiresAt: (payload.exp ?? 0) * 1000,
    };
  }

  revoke(context: Pick<AuthContext, 'jti' | 'expiresAt'>): void {
    this.revoked.set(context.jti, Math.floor(context.expiresAt / 1000));
    this.prune();
  }

  get revokedCount(): number {
    return this.revoked.size;
  }

  private prune(): void {
    const nowSeconds = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.revoked) {
      if (exp <= nowSeconds) this.revoked.delete(jti);
    }
  }
}
