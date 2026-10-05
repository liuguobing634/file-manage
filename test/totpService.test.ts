import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import type { TotpSettings } from '../src/config.js';
import { JsonStore } from '../src/services/store.js';
import { base32Decode, totpAt, type HmacAlgorithm } from '../src/services/totp.js';
import { TotpService, totpDefaults, type TotpState } from '../src/services/totpService.js';

let workspace: string;
let stateFile: string;

before(async () => {
  workspace = await fsp.realpath(await fsp.mkdtemp(path.join(os.tmpdir(), 'fm-totpsvc-')));
  stateFile = path.join(workspace, 'totp.json');
});

after(async () => {
  if (workspace) await fsp.rm(workspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function settings(overrides: Partial<TotpSettings> = {}): TotpSettings {
  return {
    issuer: 'file-manage',
    digits: 6,
    period: 30,
    algorithm: 'SHA1',
    window: 30,
    preventReplay: false,
    ...overrides,
  };
}

function service(config: TotpSettings, file = stateFile): TotpService {
  return new TotpService(new JsonStore<TotpState>(file, totpDefaults), config, 'admin');
}

function code(secret: string, config: TotpSettings, offsetSeconds = 0): string {
  return totpAt(base32Decode(secret), Date.now() + offsetSeconds * 1000, {
    digits: config.digits,
    period: config.period,
    algorithm: config.algorithm.toLowerCase() as HmacAlgorithm,
  }).code;
}

describe('TotpService 绑定参数快照', () => {
  test('SHA256 绑定流程可用（算法可配置）', async () => {
    const file = path.join(workspace, 'sha256.json');
    const config = settings({ algorithm: 'SHA256' });
    const svc = service(config, file);

    const setup = await svc.setup();
    assert.match(setup.otpauthUrl, /algorithm=SHA256/);
    assert.equal(setup.algorithm, 'SHA256');

    const activated = await svc.activate(code(setup.secret, config));
    assert.ok(activated.enabledAt);

    // 用错算法算出来的验证码必须被拒绝
    await assert.rejects(() => svc.consume(code(setup.secret, settings({ algorithm: 'SHA1' }))), /验证码|无效/);
    await svc.consume(code(setup.secret, config));
  });

  test('生成后修改环境变量里的算法/位数/周期，已绑定的验证器仍然有效', async () => {
    const file = path.join(workspace, 'drift.json');
    const original = settings({ algorithm: 'SHA1', digits: 6, period: 30 });
    const first = service(original, file);
    const setup = await first.setup();
    await first.activate(code(setup.secret, original));

    // 模拟运维改了 .env 后重启：新的 settings 与绑定快照不同
    const drifted = settings({ algorithm: 'SHA256', digits: 8, period: 60 });
    const second = service(drifted, file);

    const status = await second.status();
    assert.equal(status.algorithm, 'SHA1', '校验参数应沿用绑定时的快照');
    assert.equal(status.digits, 6);
    assert.equal(status.period, 30);
    assert.equal(status.paramsChanged, true, '应提示环境变量与绑定参数不一致');

    // 旧验证器（SHA1/6位/30秒）依旧能通过校验
    await second.consume(code(setup.secret, original));
    // 用新环境变量算出来的验证码反而不该通过
    await assert.rejects(() => second.consume(code(setup.secret, drifted)));
  });

  test('未绑定时 status 返回环境变量里的参数', async () => {
    const file = path.join(workspace, 'fresh.json');
    const svc = service(settings({ algorithm: 'SHA512', digits: 8, period: 60 }), file);
    const status = await svc.status();
    assert.equal(status.configured, false);
    assert.equal(status.algorithm, 'SHA512');
    assert.equal(status.digits, 8);
    assert.equal(status.period, 60);
    assert.equal(status.paramsChanged, false);
  });

  test('setup 只能成功一次，reset 后可以重新生成', async () => {
    const file = path.join(workspace, 'once.json');
    const svc = service(settings(), file);
    const setup = await svc.setup();
    await assert.rejects(() => svc.setup(), /已生成/);

    const reset = await svc.reset();
    assert.deepEqual(reset, { hadSecret: true, wasEnabled: false });
    assert.equal((await svc.status()).configured, false);

    const again = await svc.setup();
    assert.notEqual(again.secret, setup.secret);
  });

  test('防重放开启时同一验证码只能用一次', async () => {
    const file = path.join(workspace, 'replay.json');
    const config = settings({ preventReplay: true, window: 30 });
    const svc = service(config, file);
    const setup = await svc.setup();
    await svc.activate(code(setup.secret, config));
    const used = code(setup.secret, config);
    // 激活时已消耗该 step，直接复用应被拒绝
    await assert.rejects(() => svc.consume(used), /已被使用/);
  });
});
