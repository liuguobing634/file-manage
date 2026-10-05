import { once } from 'node:events';
import fsp from 'node:fs/promises';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../../src/app.js';
import { buildConfig, type Config } from '../../src/config.js';
import { createContext, type AppContext } from '../../src/context.js';
import { createSilentLogger } from '../../src/logger.js';
import { base32Decode, totpAt, type HmacAlgorithm } from '../../src/services/totp.js';

export interface TestEnv {
  workspace: string;
  rootA: string;
  rootB: string;
  dataDir: string;
  config: Config;
  ctx: AppContext;
  server: Server;
  baseUrl: string;
  password: string;
  close(): Promise<void>;
}

export interface StartOptions {
  adminPassword?: string;
  adminPasswordHash?: string;
  extraEnv?: Record<string, string>;
}

export async function startTestServer(options: StartOptions = {}): Promise<TestEnv> {
  // 先解析真实路径：Windows 临时目录可能是 8.3 短名，而 realpath 会返回长名
  const workspace = await fsp.realpath(await fsp.mkdtemp(path.join(os.tmpdir(), 'file-manage-test-')));
  const rootA = path.join(workspace, 'rootA');
  const rootB = path.join(workspace, 'rootB');
  const dataDir = path.join(workspace, 'data');
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.mkdir(rootB, { recursive: true });

  const password = options.adminPassword ?? 'test-password-123';
  const env: NodeJS.ProcessEnv = {
    ADMIN_USERNAME: 'admin',
    ADMIN_PASSWORD: password,
    JWT_SECRET: 'test-secret-0123456789abcdef0123456789abcdef',
    ALLOWED_ROOTS: [rootA, rootB].join(','),
    DATA_DIR: dataDir,
    LOG_LEVEL: 'error',
    SERVE_STATIC: 'false',
    TOTP_WINDOW: '30',
    ...(options.extraEnv ?? {}),
  };
  if (options.adminPasswordHash) {
    env['ADMIN_PASSWORD_HASH'] = options.adminPasswordHash;
    delete env['ADMIN_PASSWORD'];
  }

  const config = buildConfig(env, { cwd: workspace, requireAuth: true });
  const ctx = await createContext(config, createSilentLogger());
  const app = createApp(ctx);
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;

  const testEnv: TestEnv = {
    workspace,
    rootA,
    rootB,
    dataDir,
    config,
    ctx,
    server,
    baseUrl,
    password,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      // 审计日志是异步追加写入的，先 flush 再删目录，避免 ENOTEMPTY
      await ctx.audit.flush();
      await fsp.rm(workspace, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
    },
  };
  return testEnv;
}

export function req(env: TestEnv, target: string, init: RequestInit & { token?: string } = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.token) headers.set('authorization', `Bearer ${init.token}`);
  if (init.body !== undefined && init.body !== null && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }
  const { token: _token, ...rest } = init;
  return fetch(`${env.baseUrl}${target}`, { ...rest, headers, redirect: 'manual' });
}

export async function json(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`响应不是 JSON (${res.status}): ${text.slice(0, 300)}`);
  }
}

export async function login(env: TestEnv, password?: string): Promise<string> {
  const res = await req(env, '/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: password ?? env.password }),
  });
  if (res.status !== 200) throw new Error(`登录失败: ${res.status} ${await res.text()}`);
  const body = (await json(res)) as { token: string };
  return body.token;
}

/** 读取持久化的 TOTP 状态 */
export async function readTotpState(
  env: TestEnv,
): Promise<{ secret: string | null; enabled: boolean; lastUsedStep: number | null; usedCount: number }> {
  const text = await fsp.readFile(path.join(env.dataDir, 'totp.json'), 'utf8');
  return JSON.parse(text) as { secret: string | null; enabled: boolean; lastUsedStep: number | null; usedCount: number };
}

/** 读取持久化的 TOTP 密钥 */
export async function readTotpSecret(env: TestEnv): Promise<string> {
  const state = await readTotpState(env);
  if (!state.secret) throw new Error('TOTP 密钥不存在');
  return state.secret;
}

/** 生成某个时间点的 TOTP 验证码（默认当前时间） */
export function codeAt(
  secret: string,
  timeMs: number = Date.now(),
  params: { digits?: number; period?: number; algorithm?: HmacAlgorithm } = {},
): string {
  return totpAt(base32Decode(secret), timeMs, {
    digits: params.digits ?? 6,
    period: params.period ?? 30,
    algorithm: params.algorithm ?? 'sha1',
  }).code;
}

/** 指定 TOTP 周期（step）的验证码 */
export function codeForStep(
  secret: string,
  step: number,
  params: { digits?: number; period?: number; algorithm?: HmacAlgorithm } = {},
): string {
  const period = params.period ?? 30;
  return codeAt(secret, step * period * 1000 + 1000, params);
}

/**
 * 取一个「未被使用过」的验证码：取「当前周期」与「上次已用周期 + 1」中的较大者。
 * 这样既不触发防重放，又一定落在服务器允许的时间窗口内（测试里 TOTP_WINDOW=30）。
 */
export async function nextTotpCode(env: TestEnv, period = 30): Promise<string> {
  const state = await readTotpState(env);
  if (!state.secret) throw new Error('TOTP 密钥不存在');
  const currentStep = Math.floor(Date.now() / 1000 / period);
  const step = Math.max(currentStep, (state.lastUsedStep ?? -1) + 1);
  return codeForStep(state.secret, step, { period });
}

/** 把一个验证码改成必然不同的验证码（用于「错误验证码」用例） */
export function corruptCode(code: string): string {
  const first = code[0] ?? '0';
  const replaced = String((Number(first) + 1) % 10);
  return `${replaced}${code.slice(1)}`;
}

/** 第 n 个未来周期的验证码 */
export function futureCode(secret: string, stepOffset: number, period = 30): string {
  return codeAt(secret, Date.now() + stepOffset * period * 1000);
}

export async function touch(filePath: string, content = 'x'): Promise<void> {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  await fsp.writeFile(filePath, content, 'utf8');
}

export { fsp, path, os };
