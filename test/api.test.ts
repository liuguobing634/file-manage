import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { hashPassword } from '../src/services/passwords.js';
import {
  codeAt,
  codeForStep,
  corruptCode,
  json,
  login,
  nextTotpCode,
  readTotpSecret,
  readTotpState,
  req,
  startTestServer,
  touch,
  type TestEnv,
} from './support/server.js';
import { readZip } from './support/zip.js';

let env: TestEnv;
let token: string;

before(async () => {
  env = await startTestServer();
  await touch(path.join(env.rootA, 'a.txt'), 'content-a');
  await touch(path.join(env.rootA, 'sub', 'b.log'), 'content-b');
  await touch(path.join(env.rootB, 'c.txt'), 'content-c');
});

after(async () => {
  if (env) await env.close();
});

describe('系统与登录', () => {
  test('GET /healthz 无需认证', async () => {
    const res = await req(env, '/healthz');
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.status, 'ok');
    assert.equal(body.name, 'file-manage');
  });

  test('未携带 token 访问受保护接口返回 401 TOKEN_MISSING', async () => {
    const res = await req(env, '/api/roots');
    assert.equal(res.status, 401);
    const body = await json(res);
    assert.equal(body.error.code, 'TOKEN_MISSING');
  });

  test('错误密码返回 401 INVALID_CREDENTIALS', async () => {
    const res = await req(env, '/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
    });
    assert.equal(res.status, 401);
    const body = await json(res);
    assert.equal(body.error.code, 'INVALID_CREDENTIALS');
  });

  test('错误账号返回 401', async () => {
    const res = await req(env, '/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'root', password: env.password }),
    });
    assert.equal(res.status, 401);
  });

  test('登录成功返回 token', async () => {
    const res = await req(env, '/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: env.password }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.tokenType, 'Bearer');
    assert.ok(body.token.length > 20);
    assert.equal(body.expiresIn, env.config.jwtTtlSeconds);
    token = body.token;
  });

  test('缺少 username 参数返回 400', async () => {
    const res = await req(env, '/api/auth/login', { method: 'POST', body: JSON.stringify({ password: 'x' }) });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'BAD_REQUEST');
  });

  test('非法 JSON 返回 400 INVALID_JSON', async () => {
    const res = await req(env, '/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{oops',
    });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'INVALID_JSON');
  });

  test('无效 token 返回 401 TOKEN_INVALID', async () => {
    const res = await req(env, '/api/roots', { token: 'not-a-jwt' });
    assert.equal(res.status, 401);
    assert.equal((await json(res)).error.code, 'TOKEN_INVALID');
  });

  test('X-Auth-Token 请求头同样可用', async () => {
    const res = await req(env, '/api/roots', { headers: { 'x-auth-token': token } });
    assert.equal(res.status, 200);
  });

  test('GET /api/auth/me 返回账号与 TOTP 状态', async () => {
    const res = await req(env, '/api/auth/me', { token });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.username, 'admin');
    assert.equal(body.totp.configured, false);
    assert.equal(body.totp.enabled, false);
    assert.ok(Date.parse(body.expiresAt) > Date.now());
  });

  test('注销后 token 失效（TOKEN_REVOKED）', async () => {
    const tempToken = await login(env);
    const logout = await req(env, '/api/auth/logout', { method: 'POST', token: tempToken });
    assert.equal(logout.status, 200);
    assert.deepEqual(await json(logout), { ok: true });
    const me = await req(env, '/api/auth/me', { token: tempToken });
    assert.equal(me.status, 401);
    assert.equal((await json(me)).error.code, 'TOKEN_REVOKED');
  });
});

describe('根目录与浏览', () => {
  test('GET /api/roots 返回多选配置的根目录', async () => {
    const res = await req(env, '/api/roots', { token });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.roots.length, 2);
    assert.equal(body.roots[0].path, env.rootA);
    assert.equal(body.roots[1].path, env.rootB);
    assert.equal(body.roots[0].readable, true);
  });

  test('GET /api/browse 不带 path 时返回根目录清单', async () => {
    const res = await req(env, '/api/browse', { token });
    const body = await json(res);
    assert.equal(body.path, null);
    assert.equal(body.entries.length, 2);
    assert.equal(body.entries[0].type, 'dir');
  });

  test('GET /api/browse 列出目录内容（目录优先）', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(env.rootA), { token });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.path, env.rootA);
    assert.equal(body.parent, null);
    assert.equal(body.count, 2);
    assert.equal(body.entries[0].name, 'sub');
    assert.equal(body.entries[0].type, 'dir');
    assert.equal(body.entries[1].name, 'a.txt');
    assert.equal(body.entries[1].size, 9);
    assert.equal(body.entries[1].ext, '.txt');
  });

  test('子目录的 parent 指向上一层', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(path.join(env.rootA, 'sub')), { token });
    const body = await json(res);
    assert.equal(body.parent, env.rootA);
    assert.equal(body.entries[0].name, 'b.log');
  });

  test('不存在的路径返回 404', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(path.join(env.rootA, 'nope')), { token });
    assert.equal(res.status, 404);
    assert.equal((await json(res)).error.code, 'NOT_FOUND');
  });

  test('授权目录之外返回 403 PATH_NOT_ALLOWED', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(os.tmpdir()), { token });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'PATH_NOT_ALLOWED');
  });

  test('../ 穿越返回 403', async () => {
    const escaping = path.join(env.rootA, '..', '..', 'etc');
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(escaping), { token });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'PATH_NOT_ALLOWED');
  });

  test('相对路径返回 400', async () => {
    const res = await req(env, '/api/browse?path=rootA', { token });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'BAD_REQUEST');
  });

  test('浏览文件而不是目录返回 400 NOT_A_DIRECTORY', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(path.join(env.rootA, 'a.txt')), { token });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'NOT_A_DIRECTORY');
  });

  test('服务数据目录不可访问', async () => {
    const res = await req(env, '/api/browse?path=' + encodeURIComponent(env.dataDir), { token });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'PATH_NOT_ALLOWED');
  });
});

describe('文件列举（多目录）', () => {
  test('POST /api/files/list 支持 @roots 魔法值与递归', async () => {
    const res = await req(env, '/api/files/list', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: ['@roots'], recursive: true }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.count, 3);
    assert.equal(body.truncated, false);
    assert.ok(body.totalSize > 0);
    assert.deepEqual(
      body.files
        .map((file: { relPath: string; root: string }) =>
          `${path.basename(file.root)}/${file.relPath}`.split(path.sep).join('/'),
        )
        .sort(),
      ['rootA/a.txt', 'rootA/sub/b.log', 'rootB/c.txt'],
    );
  });

  test('扩展名过滤大小写不敏感且可省略点号', async () => {
    const res = await req(env, '/api/files/list', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [env.rootA], recursive: true, extensions: ['LOG'] }),
    });
    const body = await json(res);
    assert.equal(body.count, 1);
    assert.equal(body.files[0].name, 'b.log');
  });

  test('nameContains 与大小过滤', async () => {
    const byName = await json(
      await req(env, '/api/files/list', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: ['@roots'], recursive: true, nameContains: 'B.' }),
      }),
    );
    assert.equal(byName.count, 1);

    const bySize = await json(
      await req(env, '/api/files/list', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: ['@roots'], recursive: true, minSize: 10 }),
      }),
    );
    assert.equal(bySize.count, 0);
  });

  test('includeDirs 与 limit / truncated', async () => {
    const withDirs = await json(
      await req(env, '/api/files/list', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: [env.rootA], recursive: true, includeDirs: true }),
      }),
    );
    assert.equal(withDirs.count, 4); // rootA 自身 + sub 目录 + a.txt + sub/b.log

    const limited = await json(
      await req(env, '/api/files/list', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: ['@roots'], recursive: true, limit: 1 }),
      }),
    );
    assert.equal(limited.count, 1);
    assert.equal(limited.truncated, true);
  });

  test('GET /api/files 单路径便捷列举', async () => {
    const res = await req(env, `/api/files?path=${encodeURIComponent(env.rootB)}&recursive=true`, { token });
    const body = await json(res);
    assert.equal(body.count, 1);
    assert.equal(body.files[0].relPath, 'c.txt');
  });

  test('不存在的路径进入 errors 数组而不整体失败', async () => {
    const res = await req(env, '/api/files/list', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [env.rootB, path.join(env.rootA, 'missing')], recursive: true }),
    });
    const body = await json(res);
    assert.equal(res.status, 200);
    assert.equal(body.count, 1);
    assert.equal(body.errors.length, 1);
    assert.equal(body.errors[0].code, 'ENOENT');
  });

  test('越界路径进入 errors 数组（PATH_NOT_ALLOWED）', async () => {
    const res = await req(env, '/api/files/list', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [os.tmpdir()] }),
    });
    const body = await json(res);
    assert.equal(res.status, 200);
    assert.equal(body.errors[0].code, 'PATH_NOT_ALLOWED');
  });

  test('缺少 paths 返回 400', async () => {
    const res = await req(env, '/api/files/list', { method: 'POST', token, body: JSON.stringify({}) });
    assert.equal(res.status, 400);
  });
});

describe('下载', () => {
  test('GET /api/files/download 下载单个文件', async () => {
    const res = await req(env, `/api/files/download?path=${encodeURIComponent(path.join(env.rootA, 'a.txt'))}`, {
      token,
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-disposition') ?? '', /attachment; filename="a\.txt"/);
    assert.equal(await res.text(), 'content-a');
  });

  test('下载支持 ?token= 查询参数', async () => {
    const res = await req(
      env,
      `/api/files/download?path=${encodeURIComponent(path.join(env.rootA, 'a.txt'))}&token=${encodeURIComponent(token)}`,
    );
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'content-a');
  });

  test('查询参数 token 对其它接口无效', async () => {
    const res = await req(env, `/api/roots?token=${encodeURIComponent(token)}`);
    assert.equal(res.status, 401);
  });

  test('下载目录返回 400 IS_A_DIRECTORY', async () => {
    const res = await req(env, `/api/files/download?path=${encodeURIComponent(env.rootA)}`, { token });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'IS_A_DIRECTORY');
  });

  test('下载越界路径返回 403', async () => {
    const res = await req(env, `/api/files/download?path=${encodeURIComponent(path.join(os.tmpdir(), 'x'))}`, { token });
    assert.equal(res.status, 403);
  });

  test('POST /api/files/download 打包为 zip', async () => {
    const res = await req(env, '/api/files/download', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [env.rootA, env.rootB], recursive: true }),
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/zip');
    assert.match(res.headers.get('content-disposition') ?? '', /^attachment; filename="files-\d{8}-\d{6}\.zip"/);

    const buffer = Buffer.from(await res.arrayBuffer());
    const entries = readZip(buffer);
    const byName = new Map(entries.map((entry) => [entry.name, entry.content.toString('utf8')]));
    assert.deepEqual([...byName.keys()].sort(), ['rootA/a.txt', 'rootA/sub/b.log', 'rootB/c.txt']);
    assert.equal(byName.get('rootA/a.txt'), 'content-a');
    assert.equal(byName.get('rootA/sub/b.log'), 'content-b');
    assert.equal(byName.get('rootB/c.txt'), 'content-c');
  });

  test('POST /api/files/download 单个文件时直接返回文件本体', async () => {
    const res = await req(env, '/api/files/download', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootB, 'c.txt')] }),
    });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-disposition') ?? '', /filename="c\.txt"/);
    assert.equal(await res.text(), 'content-c');
  });

  test('打包时没有可下载文件返回 404', async () => {
    const res = await req(env, '/api/files/download', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [env.rootB], extensions: ['.nomatch'] }),
    });
    assert.equal(res.status, 404);
  });
});

describe('TOTP 绑定流程', () => {
  let secret: string;

  test('未删除前 status 未配置', async () => {
    const res = await req(env, '/api/totp/status', { token });
    const body = await json(res);
    assert.equal(body.configured, false);
    assert.equal(body.enabled, false);
    assert.equal(body.digits, 6);
    assert.equal(body.period, 30);
    assert.equal(body.algorithm, 'SHA1');
  });

  test('删除操作缺少 totp 参数返回 400 TOTP_REQUIRED', async () => {
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootA, 'a.txt')] }),
    });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'TOTP_REQUIRED');
  });

  test('未绑定 TOTP 时删除被拒绝（403 TOTP_NOT_ENABLED）', async () => {
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootA, 'a.txt')], totp: '123456' }),
    });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'TOTP_NOT_ENABLED');
  });

  test('DELETE /api/files 同样生效', async () => {
    const res = await req(env, '/api/files', {
      method: 'DELETE',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootA, 'a.txt')] }),
    });
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error.code, 'TOTP_REQUIRED');
  });

  test('POST /api/totp/setup 生成密钥与二维码', async () => {
    const res = await req(env, '/api/totp/setup', { method: 'POST', token, body: JSON.stringify({}) });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.match(body.secret, /^[A-Z2-7]{32}$/);
    assert.match(body.otpauthUrl, /^otpauth:\/\/totp\/file-manage:admin\?/);
    assert.match(body.qrCodeDataUrl, /^data:image\/png;base64,/);
    secret = body.secret;
  });

  test('重复 setup 返回 409 TOTP_ALREADY_CONFIGURED', async () => {
    const res = await req(env, '/api/totp/setup', { method: 'POST', token, body: JSON.stringify({}) });
    assert.equal(res.status, 409);
    const body = await json(res);
    assert.equal(body.error.code, 'TOTP_ALREADY_CONFIGURED');
    assert.match(body.error.message, /cli\/totp\.js reset/);
  });

  test('密钥已持久化且与返回一致', async () => {
    assert.equal(await readTotpSecret(env), secret);
  });

  test('GET /api/totp/qrcode 返回 PNG（支持 ?token=）', async () => {
    const res = await req(env, `/api/totp/qrcode?token=${encodeURIComponent(token)}`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'image/png');
    const buffer = Buffer.from(await res.arrayBuffer());
    assert.deepEqual([...buffer.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47]);
  });

  test('错误验证码无法激活（403 TOTP_INVALID）', async () => {
    const wrong = corruptCode(await nextTotpCode(env));
    const res = await req(env, '/api/totp/verify', { method: 'POST', token, body: JSON.stringify({ code: wrong }) });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'TOTP_INVALID');
  });

  test('验证码格式错误返回 400', async () => {
    const res = await req(env, '/api/totp/verify', { method: 'POST', token, body: JSON.stringify({ code: 'abcdef' }) });
    assert.equal(res.status, 400);
  });

  test('正确验证码完成激活', async () => {
    const res = await req(env, '/api/totp/verify', {
      method: 'POST',
      token,
      body: JSON.stringify({ code: await nextTotpCode(env) }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.enabled, true);
    assert.ok(body.enabledAt);
  });

  test('激活后 status 显示已启用', async () => {
    const body = await json(await req(env, '/api/totp/status', { token }));
    assert.equal(body.configured, true);
    assert.equal(body.enabled, true);
    assert.equal(body.usedCount, 0);
  });

  test('重复激活返回 409 TOTP_ALREADY_ENABLED', async () => {
    const res = await req(env, '/api/totp/verify', {
      method: 'POST',
      token,
      body: JSON.stringify({ code: await nextTotpCode(env) }),
    });
    assert.equal(res.status, 409);
    assert.equal((await json(res)).error.code, 'TOTP_ALREADY_ENABLED');
  });
});

describe('删除（TOTP 二次验证 + 防重放）', () => {
  let usedCode = '';

  before(async () => {
    await touch(path.join(env.rootA, 'to-delete.txt'), 'delete-me');
  });

  test('错误验证码返回 403 TOTP_INVALID 且文件仍存在', async () => {
    const target = path.join(env.rootA, 'to-delete.txt');
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [target], totp: corruptCode(await nextTotpCode(env)) }),
    });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'TOTP_INVALID');
    assert.equal((await fsp.stat(target)).isFile(), true);
  });

  test('重新使用激活时的验证码被拒绝（防重放）', async () => {
    const state = await readTotpState(env);
    assert.ok(state.lastUsedStep !== null);
    const activationCode = codeForStep(state.secret!, state.lastUsedStep!);
    const target = path.join(env.rootA, 'to-delete.txt');
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [target], totp: activationCode }),
    });
    assert.equal(res.status, 403);
    const body = await json(res);
    assert.equal(body.error.code, 'TOTP_INVALID');
    assert.match(body.error.message, /已被使用/);
    assert.equal((await fsp.stat(target)).isFile(), true);
  });

  test('正确验证码删除文件成功', async () => {
    const target = path.join(env.rootA, 'to-delete.txt');
    usedCode = await nextTotpCode(env);
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [target], totp: usedCode }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.count, 1);
    assert.equal(body.deleted[0].path, target);
    assert.equal(body.failed.length, 0);
    await assert.rejects(() => fsp.stat(target));
  });

  test('同一验证码不能重复使用', async () => {
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootB, 'c.txt')], totp: usedCode }),
    });
    assert.equal(res.status, 403);
    assert.equal((await json(res)).error.code, 'TOTP_INVALID');
  });

  test('禁止删除授权根目录本身', async () => {
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [env.rootA], totp: await nextTotpCode(env) }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.count, 0);
    assert.equal(body.failed[0].code, 'ROOT_DELETE_FORBIDDEN');
    assert.ok((await fsp.stat(env.rootA)).isDirectory());
  });

  test('越界路径删除失败但不影响其它条目', async () => {
    const target = path.join(env.rootB, 'c.txt');
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [os.tmpdir(), target], totp: await nextTotpCode(env) }),
    });
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.count, 1);
    assert.equal(body.deleted[0].path, target);
    assert.equal(body.failed[0].code, 'PATH_NOT_ALLOWED');
  });

  test('非空目录需 recursive=true', async () => {
    const dir = path.join(env.rootA, 'sub');
    const withoutRecursive = await json(
      await req(env, '/api/files/delete', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: [dir], totp: await nextTotpCode(env) }),
      }),
    );
    assert.equal(withoutRecursive.count, 0);
    assert.equal(withoutRecursive.failed[0].code, 'DIRECTORY_NOT_EMPTY');

    const withRecursive = await json(
      await req(env, '/api/files/delete', {
        method: 'POST',
        token,
        body: JSON.stringify({ paths: [dir], recursive: true, totp: await nextTotpCode(env) }),
      }),
    );
    assert.equal(withRecursive.count, 1);
    assert.equal(withRecursive.deleted[0].type, 'dir');
    await assert.rejects(() => fsp.stat(dir));
  });

  test('删除不存在的路径进入 failed 数组', async () => {
    const res = await req(env, '/api/files/delete', {
      method: 'POST',
      token,
      body: JSON.stringify({ paths: [path.join(env.rootA, 'ghost.txt')], totp: await nextTotpCode(env) }),
    });
    const body = await json(res);
    assert.equal(body.count, 0);
    assert.equal(body.failed[0].code, 'NOT_FOUND');
  });

  test('审计日志记录了登录 / TOTP / 删除操作', async () => {
    await env.ctx.audit.flush();
    const content = await fsp.readFile(path.join(env.dataDir, 'audit.log'), 'utf8');
    const actions = content
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { action: string });
    const set = new Set(actions.map((item) => item.action));
    assert.ok(set.has('login'));
    assert.ok(set.has('login_failed'));
    assert.ok(set.has('totp_setup'));
    assert.ok(set.has('totp_activate'));
    assert.ok(set.has('delete'));
    assert.ok(content.includes('to-delete.txt'));
  });
});

describe('登录限流', () => {
  test('超过失败次数后返回 429 且带 Retry-After', async () => {
    const limited = await startTestServer({
      extraEnv: { LOGIN_RATE_MAX_ATTEMPTS: '3', LOGIN_RATE_WINDOW_SECONDS: '600' },
    });
    try {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const res = await req(limited, '/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: 'admin', password: 'nope' }),
        });
        assert.equal(res.status, 401);
      }
      const blocked = await req(limited, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: 'nope' }),
      });
      assert.equal(blocked.status, 429);
      assert.equal((await json(blocked)).error.code, 'RATE_LIMITED');
      assert.ok(Number(blocked.headers.get('retry-after')) > 0);

      // 即使密码正确，在限流窗口内也拒绝
      const stillBlocked = await req(limited, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: limited.password }),
      });
      assert.equal(stillBlocked.status, 429);
    } finally {
      await limited.close();
    }
  });

  test('登录成功会清空失败计数', async () => {
    const limited = await startTestServer({ extraEnv: { LOGIN_RATE_MAX_ATTEMPTS: '3' } });
    try {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await req(limited, '/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: 'admin', password: 'nope' }),
        });
      }
      const ok = await req(limited, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: limited.password }),
      });
      assert.equal(ok.status, 200);
      const after = await req(limited, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: 'nope' }),
      });
      assert.equal(after.status, 401);
    } finally {
      await limited.close();
    }
  });
});

describe('非默认 TOTP 参数（SHA256 / 8 位）', () => {
  test('TOTP_ALGORITHM=SHA256 时 setup / verify / 删除全链路可用', async () => {
    const custom = await startTestServer({ extraEnv: { TOTP_ALGORITHM: 'SHA256', TOTP_DIGITS: '8' } });
    try {
      const customToken = await login(custom);
      const status = await json(await req(custom, '/api/totp/status', { token: customToken }));
      assert.equal(status.algorithm, 'SHA256');
      assert.equal(status.digits, 8);

      const setup = await json(
        await req(custom, '/api/totp/setup', { method: 'POST', token: customToken, body: '{}' }),
      );
      assert.match(setup.otpauthUrl, /algorithm=SHA256/);
      assert.match(setup.otpauthUrl, /digits=8/);

      // 8 位、SHA256 的验证码（TOTP_WINDOW=30 便于连续用多个周期）
      const codeFor = (offsetSeconds = 0): string =>
        codeAt(setup.secret, Date.now() + offsetSeconds * 1000, { digits: 8, algorithm: 'sha256' });

      const verify = await req(custom, '/api/totp/verify', {
        method: 'POST',
        token: customToken,
        body: JSON.stringify({ code: codeFor() }),
      });
      assert.equal(verify.status, 200, await verify.text());

      await touch(path.join(custom.rootA, 'sha256-target.txt'), 'x');
      const del = await req(custom, '/api/files/delete', {
        method: 'POST',
        token: customToken,
        body: JSON.stringify({ paths: [path.join(custom.rootA, 'sha256-target.txt')], totp: codeFor(30) }),
      });
      const delBody = await json(del);
      assert.equal(del.status, 200, JSON.stringify(delBody));
      assert.equal(delBody.count, 1, JSON.stringify(delBody));
    } finally {
      await custom.close();
    }
  });
});

describe('命令行重置 TOTP 后服务端立即感知（跨进程）', () => {
  test('外部删除 totp.json 等价于 CLI reset，无需重启服务', async () => {
    const isolated = await startTestServer();
    try {
      const isolatedToken = await login(isolated);
      const setup = await json(
        await req(isolated, '/api/totp/setup', { method: 'POST', token: isolatedToken, body: '{}' }),
      );
      const activated = await req(isolated, '/api/totp/verify', {
        method: 'POST',
        token: isolatedToken,
        body: JSON.stringify({ code: codeAt(setup.secret, Date.now()) }),
      });
      assert.equal(activated.status, 200);
      assert.equal((await json(await req(isolated, '/api/totp/status', { token: isolatedToken }))).enabled, true);

      // 模拟 `node dist/cli/totp.js reset`：另一个进程直接删掉状态文件
      await fsp.unlink(path.join(isolated.dataDir, 'totp.json'));

      const afterReset = await json(await req(isolated, '/api/totp/status', { token: isolatedToken }));
      assert.equal(afterReset.configured, false);
      assert.equal(afterReset.enabled, false);

      // 重置后可以重新 setup（不会误报 TOTP_ALREADY_CONFIGURED）
      const secondSetup = await req(isolated, '/api/totp/setup', { method: 'POST', token: isolatedToken, body: '{}' });
      assert.equal(secondSetup.status, 200);
      const secondBody = await json(secondSetup);
      assert.notEqual(secondBody.secret, setup.secret);

      // 旧密钥的验证码不再被接受
      const staleCode = await req(isolated, '/api/files/delete', {
        method: 'POST',
        token: isolatedToken,
        body: JSON.stringify({ paths: [path.join(isolated.rootA, 'whatever.txt')], totp: codeAt(setup.secret, Date.now()) }),
      });
      assert.equal(staleCode.status, 403);
      assert.equal((await json(staleCode)).error.code, 'TOTP_NOT_ENABLED');
    } finally {
      await isolated.close();
    }
  });
});

describe('scrypt 密码哈希登录', () => {
  test('ADMIN_PASSWORD_HASH 可用且明文不再接受', async () => {
    const password = 'hashed-password-42';
    const hash = await hashPassword(password);
    const hashed = await startTestServer({ adminPasswordHash: hash });
    try {
      const ok = await req(hashed, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password }),
      });
      assert.equal(ok.status, 200);

      const plaintextAttempt = await req(hashed, '/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: hash }),
      });
      assert.equal(plaintextAttempt.status, 401);
    } finally {
      await hashed.close();
    }
  });
});
