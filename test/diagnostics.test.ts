import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import {
  collectRootProblems,
  describeRoot,
  identityText,
  permissionAdvice,
  probeWritableDir,
  processIdentity,
} from '../src/services/diagnostics.js';
import type { RootInfo } from '../src/services/pathGuard.js';
import { PathGuard } from '../src/services/pathGuard.js';

let workspace: string;
let writableDir: string;

before(async () => {
  workspace = await fsp.realpath(await fsp.mkdtemp(path.join(os.tmpdir(), 'fm-diag-')));
  writableDir = path.join(workspace, 'writable');
  await fsp.mkdir(writableDir, { recursive: true });
});

after(async () => {
  if (workspace) await fsp.rm(workspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function fakeRoot(overrides: Partial<RootInfo> = {}): RootInfo {
  return {
    id: 'r0',
    path: '/data',
    exists: true,
    readable: true,
    writable: true,
    traversable: true,
    uid: 1000,
    gid: 1000,
    mode: '755',
    ...overrides,
  };
}

describe('诊断工具', () => {
  test('进程身份可读（容器里应为 uid=1000）', () => {
    const identity = processIdentity();
    assert.ok(identity.uid === null || Number.isInteger(identity.uid));
    assert.ok(typeof identityText(identity) === 'string' && identityText(identity).length > 0);
  });

  test('probeWritableDir：可写目录返回 ok', async () => {
    const result = await probeWritableDir(writableDir);
    assert.equal(result.ok, true);
    // 探测文件必须被清理掉
    assert.deepEqual(await fsp.readdir(writableDir), []);
  });

  test('probeWritableDir：目标是已存在的文件时失败', async () => {
    const file = path.join(workspace, 'a-file.txt');
    await fsp.writeFile(file, 'x', 'utf8');
    const result = await probeWritableDir(file);
    assert.equal(result.ok, false);
    assert.ok(result.code);
  });

  test('collectRootProblems：识别不存在 / 缺少进入权限 / 不可读 / 不可写', () => {
    assert.deepEqual(collectRootProblems([fakeRoot()]), []);

    const missing = collectRootProblems([fakeRoot({ exists: false })]);
    assert.equal(missing.length, 1);
    assert.equal(missing[0]!.kind, 'missing');

    const noExec = collectRootProblems([fakeRoot({ traversable: false, readable: false, writable: false })]);
    assert.equal(noExec.length, 1, '缺少 x 权限时不再重复报不可写');
    assert.equal(noExec[0]!.kind, 'untraversable');

    const unreadable = collectRootProblems([fakeRoot({ readable: false, writable: false })]);
    assert.equal(unreadable.length, 1);
    assert.equal(unreadable[0]!.kind, 'unreadable');

    const unwritable = collectRootProblems([fakeRoot({ writable: false })]);
    assert.equal(unwritable.length, 1);
    assert.equal(unwritable[0]!.kind, 'unwritable');
  });

  test('describeRoot 输出包含属主与权限位', () => {
    const text = describeRoot(fakeRoot({ path: '/data/backups', uid: 0, gid: 0, mode: '700', readable: false }));
    assert.match(text, /\/data\/backups/);
    assert.match(text, /属主=0:0/);
    assert.match(text, /权限=700/);
    assert.match(text, /R=n/);
  });

  test('permissionAdvice 给出可执行的修复命令', () => {
    const advice = permissionAdvice('/data/backups', 'read').join('\n');
    assert.match(advice, /chown -R/);
    assert.match(advice, /chmod -R o\+rX/);
    assert.match(advice, /setfacl/);
    assert.match(advice, /SELinux/);
    assert.match(advice, /user: "0:0"/);

    const writeAdvice = permissionAdvice('/var/lib/file-manage', 'write').join('\n');
    assert.match(writeAdvice, /rwX/);
  });

  test('rootsInfo 返回属主 / 权限位 / R-W-X', async () => {
    const guard = new PathGuard([writableDir]);
    const [info] = await guard.rootsInfo();
    assert.ok(info);
    assert.equal(info.exists, true);
    assert.equal(info.readable, true);
    assert.equal(info.traversable, true);
    assert.equal(info.writable, true);
    assert.match(info.mode ?? '', /^[0-7]{3}$/);
  });
});
