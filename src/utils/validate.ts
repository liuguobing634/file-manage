import { AppError } from '../errors.js';

export type Source = Record<string, unknown>;

/** 把标量（含 query 中重复 key 的数组）统一成字符串 */
export function coerceScalar(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.length > 0 ? coerceScalar(value[0]) : undefined;
  return undefined;
}

export function asObject(value: unknown): Source {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw AppError.badRequest('BAD_REQUEST', '请求体必须是 JSON 对象');
  }
  return value as Source;
}

export function optString(source: Source, key: string, options: { maxLength?: number; lowercase?: boolean } = {}): string | undefined {
  const raw = coerceScalar(source[key]);
  if (raw === undefined) return undefined;
  let value = raw.trim();
  if (value === '') return undefined;
  if (options.maxLength !== undefined && value.length > options.maxLength) {
    throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 长度不能超过 ${options.maxLength}`);
  }
  if (options.lowercase) value = value.toLowerCase();
  return value;
}

export function reqString(source: Source, key: string, options: { maxLength?: number; lowercase?: boolean } = {}): string {
  const value = optString(source, key, options);
  if (value === undefined) throw AppError.badRequest('BAD_REQUEST', `缺少必填参数 ${key}`);
  return value;
}

export function optBool(source: Source, key: string, fallback: boolean): boolean {
  const raw = coerceScalar(source[key]);
  if (raw === undefined) return fallback;
  const v = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off', ''].includes(v)) return false;
  throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 必须是布尔值 (true/false)`);
}

export function optInt(
  source: Source,
  key: string,
  options: { def: number; min?: number; max?: number },
): number {
  const raw = coerceScalar(source[key]);
  if (raw === undefined || raw.trim() === '') return options.def;
  const value = Number(raw);
  const min = options.min ?? 0;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < min || value > max) {
    throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 必须是 ${min} ~ ${max} 之间的整数`);
  }
  return value;
}

export function optStringArray(
  source: Source,
  key: string,
  options: { max?: number; maxLength?: number; splitComma?: boolean; def?: string[] } = {},
): string[] {
  const raw = source[key];
  let items: unknown[];
  if (raw === undefined || raw === null) return options.def ?? [];
  if (Array.isArray(raw)) items = raw;
  else if (typeof raw === 'string') items = options.splitComma ? raw.split(',') : [raw];
  else items = [raw];

  const out: string[] = [];
  for (const item of items) {
    const text = coerceScalar(item);
    if (text === undefined) continue;
    const trimmed = text.trim();
    if (trimmed === '') continue;
    if (options.maxLength !== undefined && trimmed.length > options.maxLength) {
      throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 中的路径过长（>${options.maxLength}）`);
    }
    if (!out.includes(trimmed)) out.push(trimmed);
  }
  if (options.max !== undefined && out.length > options.max) {
    throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 最多允许 ${options.max} 项，当前 ${out.length} 项`);
  }
  return out;
}

export function reqStringArray(
  source: Source,
  key: string,
  options: { max?: number; maxLength?: number; splitComma?: boolean } = {},
): string[] {
  const values = optStringArray(source, key, options);
  if (values.length === 0) throw AppError.badRequest('BAD_REQUEST', `缺少必填参数 ${key}（非空字符串数组）`);
  return values;
}

export function reqPattern(source: Source, key: string, pattern: RegExp, describe: string): string {
  const value = reqString(source, key, { maxLength: 64 });
  if (!pattern.test(value)) throw AppError.badRequest('BAD_REQUEST', `参数 ${key} ${describe}`);
  return value;
}

export function optEnum<T extends string>(source: Source, key: string, allowed: readonly T[], fallback: T): T {
  const raw = optString(source, key, { lowercase: true });
  if (raw === undefined) return fallback;
  const found = allowed.find((item) => item.toLowerCase() === raw);
  if (found === undefined) {
    throw AppError.badRequest('BAD_REQUEST', `参数 ${key} 只能是 ${allowed.join(' / ')}`);
  }
  return found;
}
