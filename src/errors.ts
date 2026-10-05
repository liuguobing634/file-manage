/**
 * 统一错误类型与错误码。
 * 所有对外错误都带有稳定的 code，便于前端与运维脚本判断。
 */
export class AppError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  /** 需要额外响应头时使用（例如 429 的 Retry-After） */
  readonly headers?: Record<string, string>;

  constructor(
    status: number,
    code: string,
    message: string,
    options: { details?: unknown; headers?: Record<string, string>; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    if (options.details !== undefined) this.details = options.details;
    if (options.headers !== undefined) this.headers = options.headers;
  }

  static badRequest(code: string, message: string, details?: unknown): AppError {
    return new AppError(400, code, message, { details });
  }

  static unauthorized(code: string, message: string, details?: unknown): AppError {
    return new AppError(401, code, message, { details });
  }

  static forbidden(code: string, message: string, details?: unknown): AppError {
    return new AppError(403, code, message, { details });
  }

  static notFound(message = '文件或目录不存在', details?: unknown): AppError {
    return new AppError(404, 'NOT_FOUND', message, { details });
  }

  static conflict(code: string, message: string, details?: unknown): AppError {
    return new AppError(409, code, message, { details });
  }

  static tooMany(message: string, retryAfterSeconds: number): AppError {
    return new AppError(429, 'RATE_LIMITED', message, {
      headers: { 'Retry-After': String(Math.max(1, Math.ceil(retryAfterSeconds))) },
    });
  }

  static internal(message = '服务器内部错误', cause?: unknown): AppError {
    return new AppError(500, 'INTERNAL_ERROR', message, { cause });
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/**
 * 启动期致命错误（配置 / 权限问题），附带可执行的修复建议。
 * server.ts 会把它打印到 stderr 并退出，便于 docker logs 直接定位。
 */
export class StartupError extends Error {
  readonly advice: string[];

  constructor(message: string, advice: string[] = []) {
    super(message);
    this.name = 'StartupError';
    this.advice = advice;
  }
}

/** 供测试断言使用的错误码常量 */
export const ErrorCodes = {
  BAD_REQUEST: 'BAD_REQUEST',
  INVALID_JSON: 'INVALID_JSON',
  PAYLOAD_TOO_LARGE: 'PAYLOAD_TOO_LARGE',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_MISSING: 'TOKEN_MISSING',
  TOKEN_INVALID: 'TOKEN_INVALID',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  RATE_LIMITED: 'RATE_LIMITED',
  PATH_NOT_ALLOWED: 'PATH_NOT_ALLOWED',
  NOT_FOUND: 'NOT_FOUND',
  NOT_A_DIRECTORY: 'NOT_A_DIRECTORY',
  IS_A_DIRECTORY: 'IS_A_DIRECTORY',
  TOTP_ALREADY_CONFIGURED: 'TOTP_ALREADY_CONFIGURED',
  TOTP_ALREADY_ENABLED: 'TOTP_ALREADY_ENABLED',
  TOTP_NOT_CONFIGURED: 'TOTP_NOT_CONFIGURED',
  TOTP_NOT_ENABLED: 'TOTP_NOT_ENABLED',
  TOTP_INVALID: 'TOTP_INVALID',
  TOTP_REQUIRED: 'TOTP_REQUIRED',
  ROOT_DELETE_FORBIDDEN: 'ROOT_DELETE_FORBIDDEN',
  DIRECTORY_NOT_EMPTY: 'DIRECTORY_NOT_EMPTY',
  TOO_MANY_PATHS: 'TOO_MANY_PATHS',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;
