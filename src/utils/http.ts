import type { NextFunction, Request, RequestHandler, Response } from 'express';

/** 包装 async 路由处理器，把 reject 交给错误中间件 */
export function asyncHandler(
  handler: (req: Request, res: Response, next: NextFunction) => unknown | Promise<unknown>,
): RequestHandler {
  return (req, res, next) => {
    void Promise.resolve(handler(req, res, next)).catch(next);
  };
}

/**
 * 生成 Content-Disposition 头，兼容中文等非 ASCII 文件名：
 * 同时给出 ASCII 回退名与 RFC 5987 的 filename*。
 */
export function contentDisposition(filename: string, type: 'attachment' | 'inline' = 'attachment'): string {
  const fallback = filename
    .replace(/[\r\n"\\]/g, '_')
    // 非 ASCII 一律替换，保证老客户端也能看到可读名字
    .replace(/[^\x20-\x7e]/g, '_')
    .slice(0, 180);
  const encoded = encodeURIComponent(filename).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `${type}; filename="${fallback || 'download'}"; filename*=UTF-8''${encoded}`;
}

export function isHiddenName(name: string): boolean {
  return name.startsWith('.') || name === 'Thumbs.db' || name === 'desktop.ini';
}

export function clientIp(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

export function timestampSuffix(date = new Date()): string {
  const pad = (n: number, width = 2): string => String(n).padStart(width, '0');
  return (
    `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}` +
    `-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`
  );
}
