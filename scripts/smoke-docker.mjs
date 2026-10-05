/**
 * 针对「已运行的容器 / 已部署实例」的冒烟测试（不启动 Node 进程）。
 *
 * 用法示例：
 *   SMOKE_BASE_URL=http://127.0.0.1:13000 \
 *   SMOKE_PASSWORD=smoke-password \
 *   SMOKE_MANAGED_DIR=/host/dir SMOKE_CONTAINER_DIR=/data \
 *   node scripts/smoke-docker.mjs
 *
 * 默认值：SMOKE_BASE_URL=http://127.0.0.1:13000, SMOKE_PASSWORD=smoke-password,
 *         SMOKE_MANAGED_DIR=./.docker-smoke/data, SMOKE_CONTAINER_DIR=/data
 */
import fsp from 'node:fs/promises';
import path from 'node:path';
import { base32Decode, totpAt } from '../dist/services/totp.js';

const BASE = process.env['SMOKE_BASE_URL'] ?? 'http://127.0.0.1:13000';
const PASSWORD = process.env['SMOKE_PASSWORD'] ?? 'smoke-password';
const USERNAME = process.env['SMOKE_USERNAME'] ?? 'admin';
const HOST_DIR = path.resolve(process.env['SMOKE_MANAGED_DIR'] ?? '.docker-smoke/data');
const CONTAINER_DIR = process.env['SMOKE_CONTAINER_DIR'] ?? '/data';
const PROBE = 'probe.txt';

let failures = 0;
const check = (label, condition, extra = '') => {
  if (condition) console.log(`  \u2713 ${label}`);
  else {
    failures += 1;
    console.log(`  \u2717 ${label} ${extra}`);
  }
};

const call = async (target, init = {}, token) => {
  const headers = new Headers(init.headers);
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (init.body) headers.set('content-type', 'application/json');
  return fetch(`${BASE}${target}`, { ...init, headers });
};

/** TOTP 参数以被验证实例的 /api/totp/status 为准（可能是 SHA256 / 8 位等自定义配置） */
let totpParams = { digits: 6, period: 30, algorithm: 'sha1' };
const code = (secret, offsetSeconds = 0) =>
  totpAt(base32Decode(secret), Date.now() + offsetSeconds * 1000, {
    digits: totpParams.digits,
    period: totpParams.period,
    algorithm: totpParams.algorithm.toLowerCase(),
  }).code;

console.log(`目标: ${BASE}   宿主机目录: ${HOST_DIR} -> 容器内: ${CONTAINER_DIR}`);

console.log('1) 健康检查与静态控制台');
const health = await call('/healthz');
check('GET /healthz 200', health.status === 200, `status=${health.status}`);
const page = await call('/');
check('GET / 返回控制台页面', page.status === 200 && (await page.text()).includes('/api/auth/login'));

console.log('2) 登录鉴权');
check('无 token 访问受保护接口 401', (await call('/api/roots')).status === 401);
check('错误密码 401', (await call('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: USERNAME, password: 'bad' }) })).status === 401);
const login = await call('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: USERNAME, password: PASSWORD }) });
const loginBody = await login.json();
check('登录成功', login.status === 200 && typeof loginBody.token === 'string', JSON.stringify(loginBody));
const token = loginBody.token;

console.log('3) 浏览 / 列举 / 下载');
const roots = await (await call('/api/roots', {}, token)).json();
check('roots 包含容器内授权目录', (roots.roots ?? []).some((r) => r.path === CONTAINER_DIR), JSON.stringify(roots.roots));
const browse = await (await call(`/api/browse?path=${encodeURIComponent(CONTAINER_DIR)}`, {}, token)).json();
check(`browse 能看到 ${PROBE}`, (browse.entries ?? []).some((e) => e.name === PROBE), JSON.stringify(browse.entries?.map((e) => e.name)));
check('越界路径 403', (await call(`/api/browse?path=${encodeURIComponent('/etc')}`, {}, token)).status === 403);
const list = await (await call('/api/files/list', { method: 'POST', body: JSON.stringify({ paths: ['@roots'], recursive: true }) }, token)).json();
check('递归列举返回文件', (list.count ?? 0) >= 1, JSON.stringify(list.errors));
const single = await call(`/api/files/download?path=${encodeURIComponent(path.posix.join(CONTAINER_DIR, PROBE))}&token=${encodeURIComponent(token)}`);
check('单文件下载内容正确', (await single.text()).includes('docker-smoke'));
const zip = await call('/api/files/download', { method: 'POST', body: JSON.stringify({ paths: [CONTAINER_DIR], recursive: true }) }, token);
const zipBuf = Buffer.from(await zip.arrayBuffer());
check('打包下载返回 ZIP', zip.headers.get('content-type') === 'application/zip' && zipBuf.subarray(0, 2).toString() === 'PK');

console.log('4) TOTP 绑定');
const status = await (await call('/api/totp/status', {}, token)).json();
totpParams = { digits: status.digits, period: status.period, algorithm: status.algorithm };
console.log(`   实例 TOTP 参数: ${totpParams.algorithm} / ${totpParams.digits} 位 / ${totpParams.period}s`);
let secret = null;
if (status.configured) {
  console.log(`  ! 该实例已绑定 TOTP（configured=${status.configured}, enabled=${status.enabled}），跳过 setup`);
  if (!status.enabled) {
    check('已配置但未激活，无法自动验证（请手动扫码激活后重跑）', false);
  }
} else {
  const setup = await call('/api/totp/setup', { method: 'POST', body: '{}' }, token);
  const setupBody = await setup.json();
  secret = setupBody.secret;
  check('setup 返回密钥与二维码', Boolean(secret) && String(setupBody.qrCodeDataUrl).startsWith('data:image/png;base64,'));
  check('重复 setup 返回 409', (await call('/api/totp/setup', { method: 'POST', body: '{}' }, token)).status === 409);
  const qr = await call(`/api/totp/qrcode?token=${encodeURIComponent(token)}`);
  check('二维码为 PNG', Buffer.from(await qr.arrayBuffer()).subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47])));
  const verify = await call('/api/totp/verify', { method: 'POST', body: JSON.stringify({ code: code(secret) }) }, token);
  check('激活成功', verify.status === 200, await verify.text());
}

console.log('5) 高危删除（TOTP 二次验证）');
const target = path.posix.join(CONTAINER_DIR, PROBE);
check('缺少 totp 参数 400', (await call('/api/files/delete', { method: 'POST', body: JSON.stringify({ paths: [target] }) }, token)).status === 400);
if (secret) {
  const del = await call(
    '/api/files/delete',
    { method: 'POST', body: JSON.stringify({ paths: [target], totp: code(secret, totpParams.period) }) },
    token,
  );
  const delBody = await del.json();
  check('正确验证码删除成功', del.status === 200 && delBody.count === 1, JSON.stringify(delBody));
  const gone = await fsp
    .stat(path.join(HOST_DIR, PROBE))
    .then(() => false)
    .catch(() => true);
  check('宿主机上文件确实被删除', gone);
} else {
  const del = await call('/api/files/delete', { method: 'POST', body: JSON.stringify({ paths: [target], totp: '000000' }) }, token);
  check('已启用实例拒绝错误验证码', del.status === 403 || del.status === 429, `status=${del.status}`);
}

console.log(failures === 0 ? '\n容器冒烟测试全部通过' : `\n容器冒烟测试失败 ${failures} 项`);
if (failures > 0) process.exit(1);
