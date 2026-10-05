import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { RootInfo } from './pathGuard.js';

export interface ProcessIdentity {
  uid: number | null;
  gid: number | null;
  user: string | null;
}

/** 当前进程的身份（容器里通常是 uid=1000 的 node 用户） */
export function processIdentity(): ProcessIdentity {
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const gid = typeof process.getgid === 'function' ? process.getgid() : null;
  let user: string | null = null;
  if (uid !== null) {
    try {
      user = os.userInfo().username;
    } catch {
      user = null;
    }
  }
  return { uid, gid, user };
}

export function identityText(identity: ProcessIdentity = processIdentity()): string {
  if (identity.uid === null) return `uid=未知（${process.platform}）`;
  return `uid=${identity.uid}${identity.user ? `(${identity.user})` : ''} gid=${identity.gid ?? '?'}`;
}

export function describeRoot(info: RootInfo): string {
  const owner = info.uid === null ? '未知' : `${info.uid}:${info.gid ?? '?'}`;
  const flags = [
    `R=${info.readable ? 'y' : 'n'}`,
    `W=${info.writable ? 'y' : 'n'}`,
    `X=${info.traversable ? 'y' : 'n'}`,
  ].join(' ');
  return `${info.path}  属主=${owner} 权限=${info.mode ?? '???'} ${flags}`;
}

/** 一句话的权限提示，用于接口报错信息 */
export function permissionHint(target: string, need: 'read' | 'write' = 'read'): string {
  const identity = processIdentity();
  const action = need === 'read' ? '读取' : '写入';
  return (
    `（当前进程 ${identityText(identity)}，需要${action} ${target}；` +
    '容器内挂载目录必须对该 uid 可读/可写，详见 readme.md「挂载目录不可读 / 不可写」）'
  );
}

/** 多行排查建议，用于启动日志与 doctor 命令 */
export function permissionAdvice(target: string, need: 'read' | 'write' = 'read'): string[] {
  const identity = processIdentity();
  const uid = identity.uid ?? 1000;
  const gid = identity.gid ?? 1000;
  const commands =
    need === 'write'
      ? [
          `  chown -R ${uid}:${gid} ${target}   # 直接改属主（最简单）`,
          `  setfacl -R -m u:${uid}:rwX ${target}   # 不想改属主时用 ACL`,
        ]
      : [
          `  chown -R ${uid}:${gid} ${target}   # 直接改属主（最简单）`,
          `  chmod -R o+rX ${target}   # 或放开 other 读+进入`,
          `  setfacl -R -m u:${uid}:rX ${target}   # 不想改属主时用 ACL`,
        ];
  return [
    `容器内进程身份: ${identityText(identity)}（镜像默认以非 root 的 node 用户运行）`,
    '可能的原因与对应修复：',
    '  1) 宿主目录的属主/权限不允许该 uid 访问：',
    ...commands,
    '  2) 目录本身缺少 x（进入）权限：即使可读也列不出内容，需要 o+x 或 ACL 里的 X',
    '  3) SELinux（RHEL / CentOS / Rocky / AlmaLinux）拦截了 bind mount：',
    `     挂载后加 :z（多容器共享）或 :Z（独占），例如： -v /宿主目录:${target}:z`,
    '  4) 实在不便调整宿主权限时，可让容器以 root 运行（compose 里加 user: "0:0"）——',
    '     功能上立即可用，但会失去非 root 加固，请自行权衡。',
  ];
}

export interface WriteProbeResult {
  ok: boolean;
  code?: string;
  message?: string;
}

/** 探测目录是否真的可写（mkdir + 写临时文件 + 删除） */
export async function probeWritableDir(dir: string): Promise<WriteProbeResult> {
  try {
    await fsp.mkdir(dir, { recursive: true });
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    return { ok: false, code: err.code, message: err.message };
  }
  const probe = path.join(dir, `.fm-write-probe-${process.pid}-${randomBytes(4).toString('hex')}`);
  try {
    await fsp.writeFile(probe, 'ok', { mode: 0o600 });
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    return { ok: false, code: err.code, message: err.message };
  } finally {
    await fsp.unlink(probe).catch(() => undefined);
  }
  return { ok: true };
}

export interface RootProblem {
  path: string;
  kind: 'missing' | 'not-directory' | 'unreadable' | 'untraversable' | 'unwritable';
  detail: string;
}

/** 汇总授权目录的可读/可写问题（启动日志与 doctor 命令共用） */
export function collectRootProblems(roots: RootInfo[]): RootProblem[] {
  const problems: RootProblem[] = [];
  for (const root of roots) {
    if (!root.exists) {
      problems.push({ path: root.path, kind: 'missing', detail: '目录不存在或不是目录（宿主机路径是否挂载错？）' });
      continue;
    }
    if (!root.traversable) {
      problems.push({
        path: root.path,
        kind: 'untraversable',
        detail: `缺少进入(x)权限，无法列出内容（属主 ${root.uid ?? '?'}:${root.gid ?? '?'} 权限 ${root.mode ?? '???'}）`,
      });
    } else if (!root.readable) {
      problems.push({
        path: root.path,
        kind: 'unreadable',
        detail: `不可读（属主 ${root.uid ?? '?'}:${root.gid ?? '?'} 权限 ${root.mode ?? '???'}）`,
      });
    }
    // 读都读不了的时候不必再重复报「不可写」，避免噪音
    if (!root.writable && root.readable && root.traversable) {
      problems.push({
        path: root.path,
        kind: 'unwritable',
        detail: '不可写：浏览/下载仍然可用，但这些目录里的删除操作会失败（需要目录的写权限）',
      });
    }
  }
  return problems;
}

/** 兼容性辅助：Node 18 以下没有 fs.constants 的某些位时退化为 R_OK */
export const ACCESS_FLAGS = {
  read: fs.constants.R_OK,
  write: fs.constants.W_OK,
  execute: fs.constants.X_OK,
};
