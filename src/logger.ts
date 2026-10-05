export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** 这些字段名会被脱敏，避免把密码 / 令牌 / 验证码写进日志 */
const SENSITIVE_KEY = /(password|passwd|pwd|token|authorization|secret|totp|code|jwt|credential)/i;

export interface Logger {
  readonly level: LogLevel;
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

export function normalizeLevel(value: string | undefined, fallback: LogLevel = 'info'): LogLevel {
  const v = (value ?? '').trim().toLowerCase();
  if (v === 'debug' || v === 'info' || v === 'warn' || v === 'error') return v;
  if (v === 'warning') return 'warn';
  if (v === 'silent' || v === 'none' || v === 'off') return 'error';
  return fallback;
}

function serializeValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (value instanceof Error) {
    return { name: value.name, message: value.message, code: (value as { code?: unknown }).code, stack: value.stack };
  }
  if (Array.isArray(value)) {
    return depth > 3 ? '[array]' : value.slice(0, 50).map((item) => serializeValue(item, depth + 1));
  }
  if (typeof value === 'object') {
    if (depth > 3) return '[object]';
    const out: Record<string, unknown> = {};
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_KEY.test(key) ? '[redacted]' : serializeValue(raw, depth + 1);
    }
    return out;
  }
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'function') return '[function]';
  return value;
}

export interface CreateLoggerOptions {
  level?: string | LogLevel;
  base?: Record<string, unknown>;
  /** 测试时可替换输出目标 */
  sink?: (line: string) => void;
}

export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const level = normalizeLevel(typeof options.level === 'string' ? options.level : options.level, 'info');
  const base = options.base ?? {};
  const write = options.sink ?? ((line: string) => process.stdout.write(`${line}\n`));
  const threshold = LEVEL_ORDER[level];

  const log = (entryLevel: LogLevel, message: string, fields?: Record<string, unknown>): void => {
    if (LEVEL_ORDER[entryLevel] < threshold) return;
    const payload: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level: entryLevel,
      msg: message,
      ...serializeValue(base, 0) as Record<string, unknown>,
      ...(fields ? serializeValue(fields, 0) as Record<string, unknown> : {}),
    };
    let line: string;
    try {
      line = JSON.stringify(payload);
    } catch {
      line = JSON.stringify({ ts: payload['ts'], level: entryLevel, msg: message, logError: 'unserializable fields' });
    }
    write(line);
  };

  return {
    level,
    debug: (message, fields) => log('debug', message, fields),
    info: (message, fields) => log('info', message, fields),
    warn: (message, fields) => log('warn', message, fields),
    error: (message, fields) => log('error', message, fields),
    child: (fields) => createLogger({ level, base: { ...base, ...fields }, ...(options.sink ? { sink: options.sink } : {}) }),
  };
}

/** 测试用：不输出任何内容 */
export function createSilentLogger(): Logger {
  return createLogger({ level: 'error', sink: () => {} });
}
