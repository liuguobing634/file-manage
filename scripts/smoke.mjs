/**
 * 端到端冒烟测试：直接以生产构建产物（dist/server.js）启动服务，
 * 覆盖登录 → 浏览 → 列举 → 下载 → TOTP 绑定 → 二次验证删除 的完整链路。
 *
 * 用法: npm run build && npm run smoke   （或 node scripts/smoke.mjs）
 */
import { spawn } from 'node:child_process';
import fsp from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { base32Decode, totpAt } from '../dist/services/totp.js';

const PORT = 34567;
const BASE = `http://127.0.0.1:${PORT}`;
let failures = 0;

function check(label, condition, extra = '') {
  if (condition) {
    console.log(`  \u2713 ${label}`);
  } else {
    failures += 1;
    console.log(`  \u2717 ${label} ${extra}`);
  }
}

const workspace = await fsp.realpath(await fsp.mkdtemp(path.join(os.tmpdir(), 'fm-smoke-')));
const dataDir = path.join(workspace, 'state');
const managed = path.join(workspace, 'managed');
await fsp.mkdir(path.join(managed, 'logs'), { recursive: true });
await fsp.writeFile(path.join(managed, 'hello.txt'), 'hello smoke', 'utf8');
await fsp.writeFile(path.join(managed, 'logs', 'a.log'), 'log line\n', 'utf8');

const env = {
  ...process.env,
  HOST: '127.0.0.1',
  PORT: String(PORT),
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'smoke-password',
  JWT_SECRET: 'smoke-secret-0123456789abcdef0123456789',
  ALLOWED_ROOTS: managed,
  DATA_DIR: dataDir,
  TOTP_WINDOW: '5',
  LOG_LEVEL: 'warn',
  // 可用 SMOKE_TOTP_ALGORITHM=SHA256 SMOKE_TOTP_DIGITS=8 验证非默认 TOTP 参数
  ...(process.env['SMOKE_TOTP_ALGORITHM'] ? { TOTP_ALGORITHM: process.env['SMOKE_TOTP_ALGORITHM'] } : {}),
  ...(process.env['SMOKE_TOTP_DIGITS'] ? { TOTP_DIGITS: process.env['SMOKE_TOTP_DIGITS'] } : {}),
};

const child = spawn(process.execPath, [fileURLToPath(new URL('../dist/server.js', import.meta.url))], {
  env,
  // cwd 指向临时目录：避免仓库里的 .env 影响这次冒烟（让结果只取决于本脚本给的 env）
  cwd: workspace,
  stdio: ['ignore', 'pipe', 'pipe'],
});
const serverLogs = [];
child.stdout.on('data', (chunk) => serverLogs.push(chunk.toString()));
child.stderr.on('data', (chunk) => serverLogs.push(chunk.toString()));

/** TOTP 参数以服务端 /api/totp/status 为准（支持 SHA256 / 8 位等非默认配置） */
let totpParams = { digits: 6, period: 30, algorithm: 'sha1' };
const code = (secret, offsetSeconds = 0) =>
  totpAt(base32Decode(secret), Date.now() + offsetSeconds * 1000, {
    digits: totpParams.digits,
    period: totpParams.period,
    algorithm: totpParams.algorithm.toLowerCase(),
  }).code;

async function call(target, init = {}, token) {
  const headers = new Headers(init.headers);
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (init.body) headers.set('content-type', 'application/json');
  return fetch(`${BASE}${target}`, { ...init, headers });
}

try {
  let ready = false;
  for (let attempt = 0; attempt < 100 && !ready; attempt += 1) {
    try {
      const res = await fetch(`${BASE}/healthz`);
      ready = res.ok;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  if (!ready) throw new Error(`服务未启动:\n${serverLogs.join('')}`);

  console.log('1) 健康检查与静态控制台');
  const health = await (await call('/healthz')).json();
  check('GET /healthz 返回 ok', health.status === 'ok', JSON.stringify(health));
  const page = await call('/');
  const html = await page.text();
  check('GET / 返回控制台页面', page.status === 200 && (page.headers.get('content-type') ?? '').includes('text/html'));
  check('页面包含控制台标记', html.includes('file-manage') && html.includes('/api/auth/login'));

  console.log('2) 登录鉴权');
  check('未带 token 访问 /api/roots 返回 401', (await call('/api/roots')).status === 401);
  const badLogin = await call('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'wrong' }),
  });
  check('错误密码返回 401', badLogin.status === 401);
  const login = await call('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'smoke-password' }),
  });
  const { token } = await login.json();
  check('登录成功并拿到 token', login.status === 200 && typeof token === 'string');

  console.log('3) 浏览与列举');
  const roots = await (await call('/api/roots', {}, token)).json();
  check('roots 返回授权目录', roots.roots?.[0]?.path === managed);
  const browse = await (await call(`/api/browse?path=${encodeURIComponent(managed)}`, {}, token)).json();
  check('browse 列出 2 个条目', browse.count === 2, JSON.stringify(browse.entries?.map((e) => e.name)));
  check('目录排在文件之前', browse.entries?.[0]?.type === 'dir');
  const list = await (
    await call('/api/files/list', { method: 'POST', body: JSON.stringify({ paths: ['@roots'], recursive: true }) }, token)
  ).json();
  check('递归列举得到 2 个文件', list.count === 2, JSON.stringify(list.errors));
  const outside = await call(`/api/browse?path=${encodeURIComponent(os.tmpdir())}`, {}, token);
  check('越界路径浏览返回 403', outside.status === 403);

  console.log('4) 下载');
  const single = await call(`/api/files/download?path=${encodeURIComponent(path.join(managed, 'hello.txt'))}`, {}, token);
  check('单文件下载内容正确', (await single.text()) === 'hello smoke');
  const queryToken = await call(
    `/api/files/download?path=${encodeURIComponent(path.join(managed, 'hello.txt'))}&token=${encodeURIComponent(token)}`,
  );
  check('下载支持 ?token=', (await queryToken.text()) === 'hello smoke');
  const zip = await call('/api/files/download', { method: 'POST', body: JSON.stringify({ paths: [managed], recursive: true }) }, token);
  const zipBuffer = Buffer.from(await zip.arrayBuffer());
  check('打包下载返回 ZIP', zip.headers.get('content-type') === 'application/zip' && zipBuffer.subarray(0, 2).toString() === 'PK');

  console.log('5) TOTP 绑定（只能生成一次）');
  const status0 = await (await call('/api/totp/status', {}, token)).json();
  check('初始状态未配置', status0.configured === false && status0.enabled === false);
  // 以服务端实际参数为准，兼容 SHA256 / 8 位等自定义配置
  totpParams = { digits: status0.digits, period: status0.period, algorithm: status0.algorithm };
  const setup = await call('/api/totp/setup', { method: 'POST', body: '{}' }, token);
  const setupBody = await setup.json();
  check('setup 返回密钥与二维码', Boolean(setupBody.secret) && setupBody.qrCodeDataUrl?.startsWith('data:image/png;base64,'));
  check(
    '绑定参数与环境变量一致',
    setupBody.algorithm === status0.algorithm && setupBody.digits === status0.digits && setupBody.period === status0.period,
  );
  const setupAgain = await call('/api/totp/setup', { method: 'POST', body: '{}' }, token);
  check('重复 setup 返回 409', setupAgain.status === 409);
  const qr = await call(`/api/totp/qrcode?token=${encodeURIComponent(token)}`);
  const qrBuffer = Buffer.from(await qr.arrayBuffer());
  check('二维码接口返回 PNG', qrBuffer.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])));

  console.log('6) 高危删除（TOTP 二次验证）');
  const noTotp = await call(
    '/api/files/delete',
    { method: 'POST', body: JSON.stringify({ paths: [path.join(managed, 'hello.txt')] }) },
    token,
  );
  check('缺少 totp 参数返回 400', noTotp.status === 400);
  const notEnabled = await call(
    '/api/files/delete',
    { method: 'POST', body: JSON.stringify({ paths: [path.join(managed, 'hello.txt')], totp: '123456' }) },
    token,
  );
  check('未激活时删除返回 403', notEnabled.status === 403);
  const verify = await call('/api/totp/verify', { method: 'POST', body: JSON.stringify({ code: code(setupBody.secret) }) }, token);
  check('正确验证码激活成功', verify.status === 200 && (await verify.json()).enabled === true);
  const wrongCode = await call(
    '/api/files/delete',
    { method: 'POST', body: JSON.stringify({ paths: [path.join(managed, 'logs', 'a.log')], totp: '000000' }) },
    token,
  );
  check('错误验证码删除返回 403', wrongCode.status === 403 || wrongCode.status === 429);
  const removeRes = await call(
    '/api/files/delete',
    {
      method: 'POST',
      body: JSON.stringify({
        paths: [path.join(managed, 'logs', 'a.log')],
        totp: code(setupBody.secret, totpParams.period),
      }),
    },
    token,
  );
  const removeBody = await removeRes.json();
  check('正确验证码删除成功', removeRes.status === 200 && removeBody.count === 1, JSON.stringify(removeBody));
  const gone = await fsp
    .stat(path.join(managed, 'logs', 'a.log'))
    .then(() => false)
    .catch(() => true);
  check('文件确实已从磁盘删除', gone);
  const rootDelete = await call(
    '/api/files/delete',
    {
      method: 'POST',
      body: JSON.stringify({ paths: [managed], totp: code(setupBody.secret, totpParams.period * 2) }),
    },
    token,
  );
  const rootBody = await rootDelete.json();
  check('禁止删除根目录本身', rootBody.failed?.[0]?.code === 'ROOT_DELETE_FORBIDDEN', JSON.stringify(rootBody));

  console.log('7) 审计日志与命令行');
  await new Promise((resolve) => setTimeout(resolve, 150));
  const audit = await fsp.readFile(path.join(dataDir, 'audit.log'), 'utf8');
  check('审计日志包含登录记录', audit.includes('"action":"login"'));
  check('审计日志包含删除记录', audit.includes('"action":"delete"') && audit.includes('a.log'));
  const totpFile = JSON.parse(await fsp.readFile(path.join(dataDir, 'totp.json'), 'utf8'));
  check('TOTP 状态已持久化且已激活', totpFile.enabled === true && totpFile.secret === setupBody.secret);
} finally {
  child.kill('SIGTERM');
  await new Promise((resolve) => setTimeout(resolve, 400));
  if (child.exitCode === null) child.kill('SIGKILL');
  await fsp.rm(workspace, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(() => {});
}

console.log(failures === 0 ? '\n冒烟测试全部通过' : `\n冒烟测试失败 ${failures} 项`);
if (failures > 0) {
  console.log('服务日志:\n' + serverLogs.join(''));
  process.exit(1);
}
