import type { AuthContext } from '../services/tokens.js';

declare global {
  namespace Express {
    interface Request {
      /** requireAuth 中间件注入的登录上下文 */
      auth?: AuthContext;
      /** 每个请求的唯一 id（同时写入响应头 X-Request-Id 与审计日志） */
      requestId?: string;
    }
  }
}

export {};
