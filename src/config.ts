import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpSettings {
  issuer: string;
  digits: number;
  period: number;
  algorithm: TotpAlgorithm;
  /** 校验时允许的时间漂移（±window 个周期） */
  window: number;
  /** 同一验证码是否只能使用一次（防重放） */
  preventReplay: boolean;
}

export interface RateLimitSettings {
  windowSeconds: number;
  maxAttempts: number;
}

export interface Config {
  host: string;
  port: number;
  trustProxy: boolean;
  logLevel: string;
  serveStatic: boolean;

  adminUsername: string;
  adminPassword?: string;
  adminPasswordHash?: string;

  jwtSecret: string;
  jwtSecretGenerated: boolean;
  jwtTtlSeconds: number;

  /** 允许管理的根目录（绝对路径，已解析软链接） */
  allowedRoots: string[];
  /** 配置了但被跳过的根目录及原因 */
  skippedRoots: Array<{ path: string; reason: string }>;

  dataDir: string;

  maxListFiles: number;
  maxListDepth: number;
  maxDeletePaths: number;
  maxZipFiles: number;

  loginRate: RateLimitSettings;
  totpRate: RateLimitSettings;

  totp: TotpSettings;
}

export class ConfigError extends Error {
  readonly problems: string[];

  constructor(problems: string[]) {
    super(`配置错误:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

/** 极简 .env 解析：不覆盖已存在的环境变量 */
export function loadEnvFile(file: string, env: NodeJS.ProcessEnv = process.env): void {
  let content: string;
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    return;
  }
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith('export ')) key = key.slice('export '.length).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
    }
    if (env[key] === undefined) env[key] = value;
  }
}

function readString(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const raw = env[key];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  return trimmed === '' ? undefined : trimmed;
}

function readInt(env: NodeJS.ProcessEnv, key: string, fallback: number, problems: string[], min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const raw = readString(env, key);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || !Number.isInteger(value) || value < min || value > max) {
    problems.push(`${key} 必须是 ${min} ~ ${max} 之间的整数，当前为 "${raw}"`);
    return fallback;
  }
  return value;
}

function readBool(env: NodeJS.ProcessEnv, key: string, fallback: boolean, problems: string[]): boolean {
  const raw = readString(env, key);
  if (raw === undefined) return fallback;
  const v = raw.toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(v)) return false;
  problems.push(`${key} 必须是布尔值 (true/false)，当前为 "${raw}"`);
  return fallback;
}

export function splitList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(/[,;\r\n]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function normalizeRoot(root: string, problems: string[], skipped: Array<{ path: string; reason: string }>): string | undefined {
  if (!path.isAbsolute(root)) {
    problems.push(`ALLOWED_ROOTS 中的 "${root}" 不是绝对路径`);
    return undefined;
  }
  const resolved = path.resolve(root);
  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    skipped.push({ path: resolved, reason: '目录不存在（已跳过，可在挂载卷之后再启动）' });
    return undefined;
  }
  if (!stat.isDirectory()) {
    problems.push(`ALLOWED_ROOTS 中的 "${resolved}" 不是目录`);
    return undefined;
  }
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

export interface LoadConfigOptions {
  env?: NodeJS.ProcessEnv;
  /** 读取 .env 文件（默认项目根目录下的 .env） */
  envFile?: string | null;
  /** 是否校验登录凭据 / JWT（CLI 工具不需要） */
  requireAuth?: boolean;
  cwd?: string;
}

export function loadConfig(options: LoadConfigOptions = {}): Config {
  const cwd = options.cwd ?? process.cwd();
  const env: NodeJS.ProcessEnv = { ...(options.env ?? process.env) };
  if (options.envFile !== null) {
    loadEnvFile(options.envFile ?? path.join(cwd, '.env'), env);
  }
  return buildConfig(env, { cwd, requireAuth: options.requireAuth ?? true });
}

export function buildConfig(env: NodeJS.ProcessEnv, options: { cwd?: string; requireAuth?: boolean } = {}): Config {
  const requireAuth = options.requireAuth ?? true;
  const cwd = options.cwd ?? process.cwd();
  const problems: string[] = [];
  const skippedRoots: Array<{ path: string; reason: string }> = [];

  const adminUsername = readString(env, 'ADMIN_USERNAME') ?? 'admin';
  const adminPassword = readString(env, 'ADMIN_PASSWORD');
  const adminPasswordHash = readString(env, 'ADMIN_PASSWORD_HASH');
  if (requireAuth) {
    if (!adminPassword && !adminPasswordHash) {
      problems.push('必须设置 ADMIN_PASSWORD 或 ADMIN_PASSWORD_HASH');
    }
    if (adminPasswordHash && !/^scrypt\$\d+\$\d+\$\d+\$[^$]+\$[^$]+$/.test(adminPasswordHash)) {
      problems.push('ADMIN_PASSWORD_HASH 格式不正确，应为 scrypt$N$r$p$saltBase64$hashBase64（可用 npm run hash-password 生成）');
    }
  }

  let jwtSecret = readString(env, 'JWT_SECRET');
  let jwtSecretGenerated = false;
  if (!jwtSecret) {
    if (requireAuth) {
      jwtSecretGenerated = true;
      jwtSecret = randomSecret();
      problems.push(
        '未设置 JWT_SECRET，已临时随机生成：进程重启后所有已签发的 token 都会失效（生产环境请显式设置）',
      );
    } else {
      jwtSecret = 'cli-only';
    }
  }

  const rootsRaw = splitList(readString(env, 'ALLOWED_ROOTS'));
  const roots: string[] = [];
  if (rootsRaw.length === 0) {
    if (requireAuth) problems.push('必须设置 ALLOWED_ROOTS（允许管理的文件夹，逗号分隔的绝对路径，可多选）');
  } else {
    for (const root of rootsRaw) {
      const normalized = normalizeRoot(root, problems, skippedRoots);
      if (normalized && !roots.includes(normalized)) roots.push(normalized);
    }
    if (requireAuth && roots.length === 0) {
      problems.push('ALLOWED_ROOTS 中没有可用的目录');
    }
  }

  const dataDirRaw = readString(env, 'DATA_DIR') ?? './data';
  const dataDir = path.resolve(cwd, dataDirRaw);

  const algorithmRaw = (readString(env, 'TOTP_ALGORITHM') ?? 'SHA1').toUpperCase();
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithmRaw)) {
    problems.push(`TOTP_ALGORITHM 仅支持 SHA1 / SHA256 / SHA512，当前为 "${algorithmRaw}"`);
  }

  const config: Config = {
    host: readString(env, 'HOST') ?? '0.0.0.0',
    port: readInt(env, 'PORT', 3000, problems, 1, 65535),
    trustProxy: readBool(env, 'TRUST_PROXY', false, problems),
    logLevel: readString(env, 'LOG_LEVEL') ?? 'info',
    serveStatic: readBool(env, 'SERVE_STATIC', true, problems),

    adminUsername,
    ...(adminPassword ? { adminPassword } : {}),
    ...(adminPasswordHash ? { adminPasswordHash } : {}),

    jwtSecret: jwtSecret ?? 'cli-only',
    jwtSecretGenerated,
    jwtTtlSeconds: readInt(env, 'JWT_TTL_SECONDS', 7200, problems, 60, 30 * 24 * 3600),

    allowedRoots: roots,
    skippedRoots,

    dataDir,

    maxListFiles: readInt(env, 'MAX_LIST_FILES', 5000, problems, 1, 1_000_000),
    maxListDepth: readInt(env, 'MAX_LIST_DEPTH', 16, problems, 1, 128),
    maxDeletePaths: readInt(env, 'MAX_DELETE_PATHS', 1000, problems, 1, 100_000),
    maxZipFiles: readInt(env, 'MAX_ZIP_FILES', 20000, problems, 1, 1_000_000),

    loginRate: {
      windowSeconds: readInt(env, 'LOGIN_RATE_WINDOW_SECONDS', 600, problems, 1, 86_400),
      maxAttempts: readInt(env, 'LOGIN_RATE_MAX_ATTEMPTS', 10, problems, 1, 100_000),
    },
    totpRate: {
      windowSeconds: readInt(env, 'TOTP_RATE_WINDOW_SECONDS', 60, problems, 1, 86_400),
      maxAttempts: readInt(env, 'TOTP_RATE_MAX_ATTEMPTS', 10, problems, 1, 100_000),
    },

    totp: {
      issuer: readString(env, 'TOTP_ISSUER') ?? 'file-manage',
      digits: readInt(env, 'TOTP_DIGITS', 6, problems, 6, 10),
      period: readInt(env, 'TOTP_PERIOD', 30, problems, 10, 300),
      algorithm: (['SHA1', 'SHA256', 'SHA512'].includes(algorithmRaw) ? algorithmRaw : 'SHA1') as TotpAlgorithm,
      window: readInt(env, 'TOTP_WINDOW', 1, problems, 0, 100),
      preventReplay: readBool(env, 'TOTP_PREVENT_REPLAY', true, problems),
    },
  };

  // 注意：fatalProblems 必须在 config 字面量求值之后计算，
  // 否则上面 readInt/readBool 追加的校验错误会被漏掉。
  const fatalProblems = problems.filter((p) => !p.startsWith('未设置 JWT_SECRET'));

  if (fatalProblems.length > 0) throw new ConfigError(fatalProblems);
  return config;
}

function randomSecret(): string {
  return randomBytes(48).toString('base64url');
}
