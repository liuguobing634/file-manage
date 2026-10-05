import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { AppError } from '../src/errors.js';
import { PathGuard } from '../src/services/pathGuard.js';

let workspace: string;
let rootA: string;
let rootB: string;
let dataDir: string;
let guard: PathGuard;
/** 目录链接（Windows 上回退为 junction）是否创建成功 */
let dirLinkSupported = true;
/** 文件软链接是否创建成功（Windows 需要开发者模式 / 管理员） */
let fileLinkSupported = true;

before(async () => {
  // 解析真实路径，避免 Windows 8.3 短名（如 LIUGUO~1）与 realpath 结果不一致
  workspace = await fsp.realpath(await fsp.mkdtemp(path.join(os.tmpdir(), 'fm-guard-')));
  rootA = path.join(workspace, 'rootA');
  rootB = path.join(workspace, 'rootB');
  dataDir = path.join(workspace, 'data');
  await fsp.mkdir(path.join(rootA, 'sub'), { recursive: true });
  await fsp.mkdir(path.join(rootB, 'nested'), { recursive: true });
  await fsp.mkdir(dataDir, { recursive: true });
  await fsp.writeFile(path.join(rootA, 'a.txt'), 'a', 'utf8');
  await fsp.writeFile(path.join(dataDir, 'totp.json'), '{"secret":null}', 'utf8');

  // 指向根目录之外的目录链接：Windows 上普通用户无法创建符号链接，
  // 但 junction 不需要特权，同样会被 realpath 解析，因此回退到 junction。
  try {
    fs.symlinkSync(os.tmpdir(), path.join(rootA, 'escape'), 'dir');
  } catch {
    try {
      fs.symlinkSync(os.tmpdir(), path.join(rootA, 'escape'), 'junction');
    } catch {
      dirLinkSupported = false;
    }
  }
  try {
    fs.symlinkSync(path.join(rootA, 'a.txt'), path.join(rootA, 'link-inside.txt'), 'file');
    fs.symlinkSync(path.join(workspace, 'nonexistent-target-xyz'), path.join(rootA, 'broken-link'), 'file');
  } catch {
    fileLinkSupported = false;
  }

  guard = new PathGuard([rootA, rootB], { denyRealPaths: [dataDir] });
});

after(async () => {
  if (workspace) await fsp.rm(workspace, { recursive: true, force: true });
});

async function expectAppError(promise: Promise<unknown>, code: string): Promise<AppError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof AppError, `期望 AppError，实际: ${String(error)}`);
    assert.equal(error.code, code);
    return error;
  }
  throw new Error(`期望抛出 ${code}，但调用成功了`);
}

describe('PathGuard 路径安全', () => {
  test('允许根目录及其后代', async () => {
    const root = await guard.resolve(rootA);
    assert.equal(root.isRoot, true);
    assert.equal(root.relPath, '.');

    const file = await guard.resolve(path.join(rootA, 'a.txt'), { mustExist: true });
    assert.equal(file.exists, true);
    assert.equal(file.relPath, 'a.txt');
    assert.equal(file.root, rootA);

    const nested = await guard.resolve(path.join(rootB, 'nested', 'nothing-yet.txt'));
    assert.equal(nested.exists, false);
    assert.equal(nested.realPath, path.join(rootB, 'nested', 'nothing-yet.txt'));
  });

  test('拒绝相对路径与空路径', async () => {
    await expectAppError(guard.resolve('rootA/a.txt'), 'BAD_REQUEST');
    await expectAppError(guard.resolve(''), 'BAD_REQUEST');
    await expectAppError(guard.resolve(undefined), 'BAD_REQUEST');
  });

  test('拒绝授权目录之外的路径', async () => {
    await expectAppError(guard.resolve(os.tmpdir()), 'PATH_NOT_ALLOWED');
    await expectAppError(guard.resolve(path.join(workspace, 'other')), 'PATH_NOT_ALLOWED');
  });

  test('拒绝 ../ 穿越（规范化后仍不在根目录内）', async () => {
    await expectAppError(guard.resolve(path.join(rootA, '..', '..')), 'PATH_NOT_ALLOWED');
    await expectAppError(guard.resolve(`${rootA}${path.sep}..${path.sep}rootB-x`), 'PATH_NOT_ALLOWED');
  });

  test('相似前缀的兄弟目录不算在根目录内', async () => {
    const sibling = `${rootA}-sibling`;
    await fsp.mkdir(sibling, { recursive: true });
    await expectAppError(guard.resolve(sibling), 'PATH_NOT_ALLOWED');
  });

  test('拒绝访问服务数据目录', async () => {
    await expectAppError(guard.resolve(path.join(dataDir, 'totp.json')), 'PATH_NOT_ALLOWED');
    assert.equal(guard.isExcluded(path.join(dataDir, 'totp.json')), true);
    assert.equal(guard.isExcluded(path.join(rootA, 'a.txt')), false);
  });

  test('allowRoot=false 时不允许操作根目录本身', async () => {
    await expectAppError(guard.resolve(rootA, { allowRoot: false }), 'ROOT_DELETE_FORBIDDEN');
    const ok = await guard.resolve(path.join(rootA, 'a.txt'), { allowRoot: false });
    assert.equal(ok.relPath, 'a.txt');
  });

  test('mustExist 时不存在则 404', async () => {
    await expectAppError(guard.resolve(path.join(rootA, 'missing.txt'), { mustExist: true }), 'NOT_FOUND');
  });

  test('目录链接逃逸被拒绝（指向根目录之外）', async (t) => {
    if (!dirLinkSupported) {
      t.skip('当前平台不支持创建目录链接');
      return;
    }
    await expectAppError(guard.resolve(path.join(rootA, 'escape')), 'PATH_NOT_ALLOWED');
    await expectAppError(guard.resolve(path.join(rootA, 'escape', 'anything')), 'PATH_NOT_ALLOWED');
  });

  test('指向根目录内部的软链接允许访问', async (t) => {
    if (!fileLinkSupported) {
      t.skip('当前平台不支持创建文件软链接（Windows 需开启开发者模式）');
      return;
    }
    const target = await guard.resolve(path.join(rootA, 'link-inside.txt'));
    assert.equal(target.exists, true);
    assert.equal(path.basename(target.realPath), 'a.txt');
  });

  test('断链软链接仍可被解析（便于删除）', async (t) => {
    if (!fileLinkSupported) {
      t.skip('当前平台不支持创建文件软链接（Windows 需开启开发者模式）');
      return;
    }
    const target = await guard.resolve(path.join(rootA, 'broken-link'));
    assert.equal(target.exists, true);
  });

  test('rootsInfo 返回容量与可读性', async () => {
    const roots = await guard.rootsInfo();
    assert.equal(roots.length, 2);
    assert.equal(roots[0]!.path, rootA);
    assert.equal(roots[0]!.exists, true);
    assert.equal(roots[0]!.readable, true);
    assert.equal(roots[0]!.id, 'r0');
    if (typeof roots[0]!.totalBytes === 'number') {
      assert.ok(roots[0]!.totalBytes! > 0);
    }
  });

  test('最长匹配优先：嵌套根目录', async () => {
    const nestedGuard = new PathGuard([rootA, path.join(rootA, 'sub')]);
    const target = await nestedGuard.resolve(path.join(rootA, 'sub', 'x.txt'));
    assert.equal(target.root, path.join(rootA, 'sub'));
    assert.equal(target.relPath, 'x.txt');
    const outer = await nestedGuard.resolve(path.join(rootA, 'a.txt'));
    assert.equal(outer.root, rootA);
  });
});
