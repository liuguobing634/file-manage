import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

export const SCRYPT_N = 16384;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
const KEY_LENGTH = 64;

/** 生成 `scrypt$N$r$p$saltBase64$hashBase64` 格式的密码哈希 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

/** 常量的字符串比较（先哈希再比较，避免长度泄漏） */
export function safeEqualString(a: string, b: string): boolean {
  const hashA = createHash('sha256').update(a, 'utf8').digest();
  const hashB = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(hashA, hashB);
}

export async function verifyScryptHash(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p) || n <= 1 || r <= 0 || p <= 0) return false;
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[4]!, 'base64');
    expected = Buffer.from(parts[5]!, 'base64');
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;
  const derived = await scrypt(password, salt, expected.length, { N: n, r, p, maxmem: 128 * 1024 * 1024 });
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

export interface CredentialSource {
  /** scrypt 哈希（优先） */
  passwordHash?: string;
  /** 明文密码（来自环境变量，仅用于兼容简单部署） */
  password?: string;
}

/** 校验登录密码：有哈希则用哈希，否则与明文做常量时间比较 */
export async function verifyPassword(password: string, source: CredentialSource): Promise<boolean> {
  if (source.passwordHash) return verifyScryptHash(password, source.passwordHash);
  if (source.password !== undefined) return safeEqualString(password, source.password);
  return false;
}
