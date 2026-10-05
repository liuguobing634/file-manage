import type { ErrorRequestHandler, RequestHandler } from 'express';
import { AppError, ErrorCodes, isAppError } from '../errors.js';
import type { Logger } from '../logger.js';

interface MappedError {
  status: number;
  code: string;
  message: string;
  details?: unknown;
  headers?: Record<string, string>;
}

export function notFoundHandler(): RequestHandler {
  return (req, _res, next) => {
    next(new AppError(404, ErrorCodes.NOT_FOUND, `接口不存在: ${req.method} ${req.path}`));
  };
}

function mapError(error: unknown): MappedError {
  if (isAppError(error)) {
    return {
      status: error.status,
      code: error.code,
      message: error.message,
      ...(error.details === undefined ? {} : { details: error.details }),
      ...(error.headers === undefined ? {} : { headers: error.headers }),
    };
  }

  const err = error as NodeJS.ErrnoException & { type?: string; status?: number; statusCode?: number };

  if (err?.type === 'entity.parse.failed') {
    return { status: 400, code: ErrorCodes.INVALID_JSON, message: '请求体不是合法的 JSON' };
  }
  if (err?.type === 'entity.too.large') {
    return { status: 413, code: ErrorCodes.PAYLOAD_TOO_LARGE, message: '请求体过大' };
  }
  if (err?.type === 'charset.unsupported' || err?.type === 'encoding.unsupported') {
    return { status: 415, code: 'UNSUPPORTED_MEDIA_TYPE', message: '不支持的请求体编码' };
  }

  switch (err?.code) {
    case 'ENOENT':
      return { status: 404, code: ErrorCodes.NOT_FOUND, message: '文件或目录不存在' };
    case 'EACCES':
    case 'EPERM':
      return { status: 403, code: 'PERMISSION_DENIED', message: '没有权限访问该路径' };
    case 'EISDIR':
      return { status: 400, code: ErrorCodes.IS_A_DIRECTORY, message: '目标是目录' };
    case 'ENOTDIR':
      return { status: 400, code: ErrorCodes.NOT_A_DIRECTORY, message: '路径中包含非目录项' };
    case 'ENOTEMPTY':
      return { status: 409, code: ErrorCodes.DIRECTORY_NOT_EMPTY, message: '目录非空' };
    case 'ELOOP':
      return { status: 403, code: ErrorCodes.PATH_NOT_ALLOWED, message: '检测到循环软链接' };
    case 'ENAMETOOLONG':
      return { status: 400, code: ErrorCodes.BAD_REQUEST, message: '路径过长' };
    default:
      break;
  }

  const status = err?.status ?? err?.statusCode;
  if (typeof status === 'number' && status >= 400 && status < 500) {
    return { status, code: 'BAD_REQUEST', message: err?.message ?? '请求错误' };
  }
  return { status: 500, code: ErrorCodes.INTERNAL_ERROR, message: '服务器内部错误' };
}

export function errorHandler(logger: Logger): ErrorRequestHandler {
  return (error, req, res, _next) => {
    const mapped = mapError(error);
    const base = {
      requestId: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: mapped.status,
      code: mapped.code,
      ip: req.ip,
    };
    if (mapped.status >= 500) {
      logger.error('请求处理失败', { ...base, error });
    } else if (mapped.status === 429) {
      logger.warn('请求被限流', base);
    } else {
      logger.debug('请求被拒绝', { ...base, reason: mapped.message });
    }

    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (mapped.headers) {
      for (const [key, value] of Object.entries(mapped.headers)) res.setHeader(key, value);
    }
    res.status(mapped.status).json({
      error: { code: mapped.code, message: mapped.message, details: mapped.details ?? null },
      requestId: req.requestId ?? null,
    });
  };
}
