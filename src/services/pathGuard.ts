import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { AppError, ErrorCodes } from '../errors.js';

export interface RootInfo {
  id: string;
  path: string;
  exists: boolean;
  /** 目录本身是否可读（浏览/下载需要） */
  readable: boolean;
  /** 是否可写（删除需要：文件所在目录的写权限） */
  writable: boolean;
  /** 是否可进入（目录的 x 位；缺失时即使可读也列不出内容） */
  traversable: boolean;
  /** 目录属主 uid（Windows 上为 0，无意义） */
  uid: number | null;
  gid: number | null;
  /** 权限位，例如 "755" */
  mode: string | null;
  totalBytes?: number;
  freeBytes?: number;
}

export interface ResolvedTarget {
  /** 规范化后的绝对路径（保留用户视角，用于返回与展示） */
  path: string;
  /** 解析软链接后的真实路径（实际文件操作一律使用它） */
  realPath: string;
  /** 所属授权根目录 */
  root: string;
  /** 相对根目录的路径，根目录自身为 '.' */
  relPath: string;
  exists: boolean;
  isRoot: boolean;
}

export interface PathGuardOptions {
  /** 这些真实路径（例如服务自身的数据目录）禁止访问 */
  denyRealPaths?: string[];
}

function compareKey(value: string): string {
  return process.platform === 'win32' ? value.toLowerCase() : value;
}

/**
 * 路径安全守卫：
 * 1. 必须使用绝对路径；
 * 2. 必须位于 ALLOWED_ROOTS 之一（或其后代）内部；
 * 3. 解析软链接后仍需位于根目录内部（防软链接逃逸）；
 * 4. 服务数据目录（TOTP 密钥、审计日志）对外不可见。
 */
export class PathGuard {
  private readonly roots: string[];
  private readonly deny: string[];
  private readonly realRootCache = new Map<string, string>();

  constructor(roots: string[], options: PathGuardOptions = {}) {
    this.roots = roots.map((root) => path.resolve(root));
    this.deny = (options.denyRealPaths ?? []).map((item) => path.resolve(item));
  }

  get allowedRoots(): string[] {
    return [...this.roots];
  }

  private static isInside(root: string, target: string): boolean {
    const r = compareKey(root);
    const t = compareKey(target);
    if (t === r) return true;
    return t.startsWith(r.endsWith(path.sep) ? r : `${r}${path.sep}`);
  }

  /** 返回覆盖该路径的最长（最具体）根目录 */
  findRoot(target: string): string | undefined {
    let best: string | undefined;
    for (const root of this.roots) {
      if (!PathGuard.isInside(root, target)) continue;
      if (best === undefined || root.length > best.length) best = root;
    }
    return best;
  }

  private async realRootOf(root: string): Promise<string> {
    const cached = this.realRootCache.get(root);
    if (cached) return cached;
    let real: string;
    try {
      real = await fsp.realpath(root);
    } catch {
      real = root;
    }
    this.realRootCache.set(root, real);
    return real;
  }

  private assertNotDenied(realPath: string): void {
    for (const denied of this.deny) {
      if (PathGuard.isInside(denied, realPath)) {
        throw AppError.forbidden(ErrorCodes.PATH_NOT_ALLOWED, `该路径属于服务数据目录，禁止访问: ${realPath}`);
      }
    }
  }

  /** 该路径是否落在禁止访问的目录内（列表过滤用，不抛错） */
  isExcluded(target: string): boolean {
    for (const denied of this.deny) {
      if (PathGuard.isInside(denied, target)) return true;
    }
    return false;
  }

  /** 逐个向上找到最深的已存在祖先并解析软链接，再拼回不存在的尾部 */
  private async resolveReal(target: string): Promise<string> {
    let current = target;
    const tail: string[] = [];
    for (;;) {
      try {
        await fsp.lstat(current);
        break;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'ENOENT' && code !== 'ENOTDIR') throw error;
        const parent = path.dirname(current);
        if (parent === current) break;
        tail.unshift(path.basename(current));
        current = parent;
      }
    }
    let realAncestor: string;
    try {
      realAncestor = await fsp.realpath(current);
    } catch {
      realAncestor = current;
    }
    return tail.length > 0 ? path.join(realAncestor, ...tail) : realAncestor;
  }

  async resolve(
    input: unknown,
    options: { mustExist?: boolean; allowRoot?: boolean } = {},
  ): Promise<ResolvedTarget> {
    if (typeof input !== 'string' || input.trim() === '') {
      throw AppError.badRequest(ErrorCodes.BAD_REQUEST, '路径不能为空');
    }
    const raw = input.trim();
    if (raw.includes('\0')) {
      throw AppError.badRequest(ErrorCodes.BAD_REQUEST, '路径包含非法字符');
    }
    if (!path.isAbsolute(raw)) {
      throw AppError.badRequest(ErrorCodes.BAD_REQUEST, `必须使用绝对路径: ${raw}`);
    }
    const abs = path.resolve(raw);
    const root = this.findRoot(abs);
    if (root === undefined) {
      throw AppError.forbidden(ErrorCodes.PATH_NOT_ALLOWED, `路径不在授权目录内: ${abs}`);
    }

    let exists = false;
    try {
      await fsp.lstat(abs);
      exists = true;
    } catch {
      exists = false;
    }

    let realPath: string;
    try {
      realPath = await this.resolveReal(abs);
    } catch (error) {
      throw AppError.forbidden(
        ErrorCodes.PATH_NOT_ALLOWED,
        `路径解析失败（可能是循环软链接）: ${abs}`,
        { cause: (error as Error).message },
      );
    }

    const realRoot = await this.realRootOf(root);
    if (!PathGuard.isInside(realRoot, realPath)) {
      throw AppError.forbidden(
        ErrorCodes.PATH_NOT_ALLOWED,
        `路径通过软链接指向授权目录之外，已拒绝: ${abs} -> ${realPath}`,
      );
    }
    this.assertNotDenied(realPath);

    if (options.mustExist && !exists) {
      throw AppError.notFound(`路径不存在: ${abs}`);
    }

    const relPath = path.relative(root, abs) || '.';
    const isRoot = relPath === '.';
    if (isRoot && options.allowRoot === false) {
      throw AppError.forbidden(ErrorCodes.ROOT_DELETE_FORBIDDEN, `不允许操作被授权的根目录本身: ${root}`);
    }

    return { path: abs, realPath, root, relPath, exists, isRoot };
  }

  async rootsInfo(): Promise<RootInfo[]> {
    const result: RootInfo[] = [];
    for (const [index, root] of this.roots.entries()) {
      const info: RootInfo = {
        id: `r${index}`,
        path: root,
        exists: false,
        readable: false,
        writable: false,
        traversable: false,
        uid: null,
        gid: null,
        mode: null,
      };
      try {
        const stat = await fsp.stat(root);
        info.exists = stat.isDirectory();
        info.uid = typeof stat.uid === 'number' ? stat.uid : null;
        info.gid = typeof stat.gid === 'number' ? stat.gid : null;
        info.mode = Number.isInteger(stat.mode) ? (stat.mode & 0o777).toString(8).padStart(3, '0') : null;
      } catch {
        info.exists = false;
      }
      // R_OK = 能否列出内容，X_OK = 能否进入该目录（目录缺少 x 位时列不出内容），W_OK = 能否在其中删除/新建
      info.readable = await this.canAccess(root, fs.constants.R_OK);
      info.writable = await this.canAccess(root, fs.constants.W_OK);
      info.traversable = await this.canAccess(root, fs.constants.X_OK);
      try {
        const stats = await fsp.statfs(root);
        info.totalBytes = Number(stats.blocks) * Number(stats.bsize);
        info.freeBytes = Number(stats.bavail) * Number(stats.bsize);
      } catch {
        /* 某些平台 / 文件系统不支持 statfs */
      }
      result.push(info);
    }
    return result;
  }

  private async canAccess(target: string, mode: number): Promise<boolean> {
    try {
      await fsp.access(target, mode);
      return true;
    } catch {
      return false;
    }
  }
}
