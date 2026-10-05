import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';

export interface TotpParams {
  digits: number;
  period: number;
  algorithm: HmacAlgorithm;
}

/** RFC 4648 Base32 编码（无填充，TOTP 密钥格式） */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

/** RFC 4648 Base32 解码，容忍空格、连字符、小写与 `=` 填充 */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (clean.length === 0) throw new Error('Base32 字符串为空');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`非法 Base32 字符: ${char}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** 生成 TOTP 密钥（Base32 字符串），默认 20 字节 = 160 bit，与 Google Authenticator 一致 */
export function generateSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

/** RFC 4226 HOTP */
export function hotp(secret: Buffer, counter: number, digits = 6, algorithm: HmacAlgorithm = 'sha1'): string {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('counter 必须是非负安全整数');
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac(algorithm, secret).update(message).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function counterFor(timeMs: number, period: number): number {
  return Math.floor(timeMs / 1000 / period);
}

/** RFC 6238 TOTP */
export function totpAt(
  secret: Buffer,
  timeMs: number,
  params: TotpParams,
): { code: string; step: number } {
  const step = counterFor(timeMs, params.period);
  return { code: hotp(secret, step, params.digits, params.algorithm), step };
}

export interface VerifyOptions extends TotpParams {
  /** 允许的周期漂移，默认 ±1 */
  window?: number;
  /** 小于等于该 step 的验证码视为已使用（防重放） */
  minStepExclusive?: number | null;
  now?: number;
}

export interface VerifyResult {
  valid: boolean;
  step: number | null;
  delta: number | null;
}

function safeEqualCode(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/** 校验 TOTP 验证码（常量时间比较 + 时间漂移 + 可选防重放） */
export function verifyTotp(secret: Buffer | string, token: string, options: VerifyOptions): VerifyResult {
  const invalid: VerifyResult = { valid: false, step: null, delta: null };
  const key = typeof secret === 'string' ? base32Decode(secret) : secret;
  const tokenText = token.trim();
  if (!new RegExp(`^\\d{${options.digits}}$`).test(tokenText)) return invalid;

  const current = counterFor(options.now ?? Date.now(), options.period);
  const window = options.window ?? 1;
  const minStep = options.minStepExclusive ?? null;

  const deltas: number[] = [0];
  for (let i = 1; i <= window; i += 1) {
    deltas.push(-i, i);
  }

  for (const delta of deltas) {
    const step = current + delta;
    if (step < 0) continue;
    if (minStep !== null && step <= minStep) continue;
    const candidate = hotp(key, step, options.digits, options.algorithm);
    if (safeEqualCode(candidate, tokenText)) return { valid: true, step, delta };
  }
  return invalid;
}

export interface OtpAuthUrlParams extends TotpParams {
  secret: string;
  issuer: string;
  account: string;
}

export function buildOtpAuthUrl(params: OtpAuthUrlParams): string {
  const label = `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.account)}`;
  const query = new URLSearchParams({
    secret: params.secret,
    issuer: params.issuer,
    algorithm: params.algorithm.toUpperCase(),
    digits: String(params.digits),
    period: String(params.period),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}
