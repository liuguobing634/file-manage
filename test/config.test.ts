import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { buildConfig, ConfigError, loadEnvFile, splitList } from '../src/config.js';

let workspace: string;
const baseEnv = (): NodeJS.ProcessEnv => ({
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'secret-password',
  ALLOWED_ROOTS: workspace,
});

before(async () => {
  workspace = await fsp.mkdtemp(path.join(os.tmpdir(), 'fm-config-'));
  await fsp.mkdir(path.join(workspace, 'logs'), { recursive: true });
});

after(async () => {
  if (workspace) await fsp.rm(workspace, { recursive: true, force: true });
});

describe('配置解析', () => {
  test('默认值', () => {
    const config = buildConfig(baseEnv(), { cwd: workspace });
    assert.equal(config.port, 3000);
    assert.equal(config.host, '0.0.0.0');
    assert.equal(config.jwtTtlSeconds, 7200);
    assert.equal(config.maxListFiles, 5000);
    assert.equal(config.maxListDepth, 16);
    assert.equal(config.maxDeletePaths, 1000);
    assert.equal(config.loginRate.maxAttempts, 10);
    assert.equal(config.totp.digits, 6);
    assert.equal(config.totp.period, 30);
    assert.equal(config.totp.algorithm, 'SHA1');
    assert.equal(config.totp.preventReplay, true);
    assert.equal(config.allowedRoots.length, 1);
    assert.equal(config.dataDir, path.join(workspace, 'data'));
  });

  test('缺少 ADMIN_PASSWORD 与 ADMIN_PASSWORD_HASH 时报错', () => {
    const env = baseEnv();
    delete env['ADMIN_PASSWORD'];
    assert.throws(() => buildConfig(env, { cwd: workspace }), (error: unknown) => {
      assert.ok(error instanceof ConfigError);
      assert.match(error.message, /ADMIN_PASSWORD/);
      return true;
    });
  });

  test('缺少 ALLOWED_ROOTS 时报错', () => {
    const env = baseEnv();
    delete env['ALLOWED_ROOTS'];
    assert.throws(() => buildConfig(env, { cwd: workspace }), /ALLOWED_ROOTS/);
  });

  test('相对路径的根目录报错', () => {
    assert.throws(
      () => buildConfig({ ...baseEnv(), ALLOWED_ROOTS: 'relative/dir' }, { cwd: workspace }),
      /不是绝对路径/,
    );
  });

  test('根目录不是目录时跳过，全部不可用则报错', async () => {
    const filePath = path.join(workspace, 'a-file.txt');
    await fsp.writeFile(filePath, 'x', 'utf8');
    assert.throws(() => buildConfig({ ...baseEnv(), ALLOWED_ROOTS: filePath }, { cwd: workspace }), /不是目录/);

    const missing = path.join(workspace, 'missing-dir');
    assert.throws(() => buildConfig({ ...baseEnv(), ALLOWED_ROOTS: missing }, { cwd: workspace }), /没有可用的目录/);
  });

  test('部分根目录不存在时跳过并记录原因', () => {
    const config = buildConfig(
      { ...baseEnv(), ALLOWED_ROOTS: `${workspace},${path.join(workspace, 'missing-dir')}` },
      { cwd: workspace },
    );
    assert.equal(config.allowedRoots.length, 1);
    assert.equal(config.skippedRoots.length, 1);
    assert.match(config.skippedRoots[0]!.reason, /不存在/);
  });

  test('未设置 JWT_SECRET 时生成临时密钥并给出告警（不阻断启动）', () => {
    const config = buildConfig(baseEnv(), { cwd: workspace });
    assert.equal(config.jwtSecretGenerated, true);
    assert.ok(config.jwtSecret.length >= 32);

    const explicit = buildConfig({ ...baseEnv(), JWT_SECRET: 'fixed-secret-value' }, { cwd: workspace });
    assert.equal(explicit.jwtSecretGenerated, false);
    assert.equal(explicit.jwtSecret, 'fixed-secret-value');
  });

  test('非法数值 / 布尔值会报错', () => {
    assert.throws(() => buildConfig({ ...baseEnv(), PORT: 'abc' }, { cwd: workspace }), /PORT/);
    assert.throws(() => buildConfig({ ...baseEnv(), PORT: '99999' }, { cwd: workspace }), /PORT/);
    assert.throws(() => buildConfig({ ...baseEnv(), SERVE_STATIC: 'maybe' }, { cwd: workspace }), /SERVE_STATIC/);
    assert.throws(() => buildConfig({ ...baseEnv(), TOTP_ALGORITHM: 'MD5' }, { cwd: workspace }), /TOTP_ALGORITHM/);
  });

  test('ADMIN_PASSWORD_HASH 格式校验', () => {
    assert.throws(
      () => buildConfig({ ...baseEnv(), ADMIN_PASSWORD_HASH: 'scrypt$1$2$3' }, { cwd: workspace }),
      /ADMIN_PASSWORD_HASH/,
    );
  });

  test('requireAuth=false 时不需要账号与根目录（供 CLI 使用）', () => {
    const config = buildConfig({ DATA_DIR: path.join(workspace, 'cli-data') }, { cwd: workspace, requireAuth: false });
    assert.equal(config.allowedRoots.length, 0);
    assert.equal(config.dataDir, path.join(workspace, 'cli-data'));
  });

  test('splitList 支持逗号 / 分号 / 换行', () => {
    assert.deepEqual(splitList('/a,/b ; /c\n/d'), ['/a', '/b', '/c', '/d']);
    assert.deepEqual(splitList(undefined), []);
    assert.deepEqual(splitList('  '), []);
  });

  test('loadEnvFile 不覆盖已有环境变量', async () => {
    const file = path.join(workspace, '.env.test');
    await fsp.writeFile(file, ['# 注释', 'A=1', 'B="quoted value"', 'export C=3', 'D=', 'INVALID LINE'].join('\n'), 'utf8');
    const env: NodeJS.ProcessEnv = { A: 'existing' };
    loadEnvFile(file, env);
    assert.equal(env['A'], 'existing');
    assert.equal(env['B'], 'quoted value');
    assert.equal(env['C'], '3');
    assert.equal(env['D'], '');
  });
});
