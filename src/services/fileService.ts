import fsp from 'node:fs/promises';
import path from 'node:path';
import { AppError, ErrorCodes } from '../errors.js';
import { isHiddenName } from '../utils/http.js';
import { permissionHint } from './diagnostics.js';
import type { PathGuard, ResolvedTarget } from './pathGuard.js';

export type EntryType = 'file' | 'dir' | 'other';

export interface FileEntry {
  path: string;
  name: string;
  type: EntryType;
  size: number;
  mtime: string | null;
  mode: string | null;
  ext: string;
  isSymlink: boolean;
  root: string;
  relPath: string;
}

export interface ListIssue {
  path: string;
  code: string;
  message: string;
}

export interface ListResult {
  files: FileEntry[];
  errors: ListIssue[];
  scanned: number;
  truncated: boolean;
  totalSize: number;
  count: number;
}

export interface ListOptions {
  paths: string[];
  recursive: boolean;
  maxDepth: number;
  includeDirs: boolean;
  showHidden: boolean;
  extensions: string[];
  nameContains?: string;
  minSize: number;
  maxSize: number;
  limit: number;
  maxDepthLimit: number;
}

export interface DirectoryListing {
  target: ResolvedTarget;
  entries: FileEntry[];
  truncated: boolean;
  count: number;
}

function compareKey(value: string): string {
  return process.platform === 'win32' ? value.toLowerCase() : value;
}

export function normalizeExtensions(input: string[]): string[] {
  const out: string[] = [];
  for (const item of input) {
    const trimmed = item.trim().toLowerCase();
    if (trimmed === '') continue;
    const withDot = trimmed.startsWith('.') ? trimmed : `.${trimmed}`;
    if (!out.includes(withDot)) out.push(withDot);
  }
  return out;
}

function errorIssue(target: string, error: unknown): ListIssue {
  const err = error as NodeJS.ErrnoException;
  const code = err?.code ?? 'ERROR';
  return { path: target, code, message: err?.message ?? String(error) };
}

function toIso(value: Date | undefined): string | null {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) return null;
  return value.toISOString();
}

async function buildEntry(absPath: string, root: string, guard: PathGuard): Promise<FileEntry> {
  const linkStat = await fsp.lstat(absPath);
  const isSymlink = linkStat.isSymbolicLink();
  if (isSymlink) {
    // 软链接必须仍然指向授权目录内部，否则视为不可见（防止通过链接读取根目录外的文件）
    await guard.resolve(absPath, { mustExist: false });
  }
  let stat = linkStat;
  if (isSymlink) {
    try {
      stat = await fsp.stat(absPath);
    } catch {
      stat = linkStat;
    }
  }
  const type: EntryType = stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other';
  const name = path.basename(absPath);
  return {
    path: absPath,
    name,
    type,
    size: type === 'file' ? stat.size : 0,
    mtime: toIso(stat.mtime),
    mode: Number.isInteger(stat.mode) ? (stat.mode & 0o777).toString(8).padStart(3, '0') : null,
    ext: type === 'file' ? path.extname(name).toLowerCase() : '',
    isSymlink,
    root,
    relPath: path.relative(root, absPath) || '.',
  };
}

function sortEntries(entries: FileEntry[]): FileEntry[] {
  return entries.sort((a, b) => {
    if (a.type !== b.type) {
      if (a.type === 'dir') return -1;
      if (b.type === 'dir') return 1;
    }
    return a.name.localeCompare(b.name, 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
  });
}

/** 浏览单个目录的直接子项 */
export async function listDirectory(
  guard: PathGuard,
  inputPath: string,
  options: { showHidden: boolean; limit: number },
): Promise<DirectoryListing> {
  const target = await guard.resolve(inputPath, { mustExist: true });
  let stat;
  try {
    stat = await fsp.stat(target.realPath);
  } catch {
    throw AppError.notFound(`路径不存在: ${target.path}`);
  }
  if (!stat.isDirectory()) {
    throw AppError.badRequest(ErrorCodes.NOT_A_DIRECTORY, `不是目录: ${target.path}`);
  }

  let dirents;
  try {
    dirents = await fsp.readdir(target.realPath, { withFileTypes: true });
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      throw AppError.forbidden(
        'PERMISSION_DENIED',
        `没有权限读取目录: ${target.path} ${permissionHint(target.path, 'read')}`,
      );
    }
    throw AppError.internal(`读取目录失败: ${target.path}: ${err.message}`);
  }

  const entries: FileEntry[] = [];
  let truncated = false;
  for (const dirent of dirents) {
    if (!options.showHidden && isHiddenName(dirent.name)) continue;
    if (entries.length >= options.limit) {
      truncated = true;
      break;
    }
    const childPath = path.join(target.path, dirent.name);
    try {
      const entry = await buildEntry(childPath, target.root, guard);
      if (guard.isExcluded(entry.path)) continue;
      entries.push(entry);
    } catch {
      /* 单个条目 stat 失败（如权限、瞬时消失、软链接越界）时跳过 */
    }
  }

  sortEntries(entries);
  return { target, entries, truncated, count: entries.length };
}

function matchFilters(entry: FileEntry, options: ListOptions): boolean {
  if (options.nameContains) {
    const needle = options.nameContains.toLowerCase();
    if (!entry.name.toLowerCase().includes(needle)) return false;
  }
  if (entry.type === 'dir') return true;
  if (options.extensions.length > 0 && !options.extensions.includes(entry.ext)) return false;
  if (options.minSize > 0 && entry.size < options.minSize) return false;
  if (options.maxSize > 0 && entry.size > options.maxSize) return false;
  return true;
}

/** 多目录（可递归）列举文件，带过滤器、数量上限与逐路径错误收集 */
export async function collectFiles(guard: PathGuard, options: ListOptions): Promise<ListResult> {
  const files: FileEntry[] = [];
  const errors: ListIssue[] = [];
  let scanned = 0;
  let truncated = false;
  let totalSize = 0;
  const visited = new Set<string>();
  const effectiveMaxDepth =
    options.maxDepth > 0 ? Math.min(options.maxDepth, options.maxDepthLimit) : options.maxDepthLimit;

  const push = (entry: FileEntry): void => {
    if (files.length >= options.limit) {
      truncated = true;
      return;
    }
    files.push(entry);
    if (entry.type === 'file') totalSize += entry.size;
  };

  const walk = async (dir: ResolvedTarget, depth: number): Promise<void> => {
    if (truncated) return;
    if (depth > effectiveMaxDepth) return;
    const key = compareKey(dir.realPath);
    if (visited.has(key)) return;
    visited.add(key);
    if (guard.isExcluded(key)) return;

    let dirents;
    try {
      dirents = await fsp.readdir(dir.realPath, { withFileTypes: true });
    } catch (error) {
      errors.push(errorIssue(dir.path, error));
      return;
    }

    for (const dirent of dirents) {
      if (truncated) return;
      if (!options.showHidden && isHiddenName(dirent.name)) continue;
      const childPath = path.join(dir.path, dirent.name);
      let entry: FileEntry;
      try {
        entry = await buildEntry(childPath, dir.root, guard);
      } catch {
        continue;
      }
      scanned += 1;

      if (entry.type === 'dir') {
        if (guard.isExcluded(entry.path)) continue;
        if (options.includeDirs && matchFilters(entry, options)) push(entry);
        if (options.recursive && !entry.isSymlink) {
          try {
            const sub = await guard.resolve(entry.path, { mustExist: false });
            await walk(sub, depth + 1);
          } catch (error) {
            errors.push(errorIssue(entry.path, error));
          }
        }
        continue;
      }

      if (entry.type === 'file' && matchFilters(entry, options)) push(entry);
    }
  };

  for (const inputPath of options.paths) {
    if (truncated) break;
    let target: ResolvedTarget;
    try {
      target = await guard.resolve(inputPath, { mustExist: false });
    } catch (error) {
      errors.push(errorIssue(inputPath, error));
      continue;
    }
    if (!target.exists) {
      errors.push({ path: target.path, code: 'ENOENT', message: '路径不存在' });
      continue;
    }
    let stat;
    try {
      stat = await fsp.stat(target.realPath);
    } catch (error) {
      errors.push(errorIssue(target.path, error));
      continue;
    }
    if (stat.isDirectory()) {
      if (options.includeDirs) {
        try {
          const dirEntry = await buildEntry(target.path, target.root, guard);
          if (matchFilters(dirEntry, options)) push(dirEntry);
        } catch {
          /* ignore */
        }
      }
      await walk(target, 1);
    } else if (stat.isFile()) {
      try {
        const entry = await buildEntry(target.path, target.root, guard);
        scanned += 1;
        if (matchFilters(entry, options)) push(entry);
      } catch (error) {
        errors.push(errorIssue(target.path, error));
      }
    }
  }

  return { files, errors, scanned, truncated, totalSize, count: files.length };
}

export interface DownloadableFile {
  target: ResolvedTarget;
  name: string;
  size: number;
  mtime: Date;
}

/** 校验单个下载目标（必须是文件） */
export async function resolveDownloadFile(guard: PathGuard, inputPath: string): Promise<DownloadableFile> {
  const target = await guard.resolve(inputPath, { mustExist: true });
  let stat;
  try {
    stat = await fsp.stat(target.realPath);
  } catch {
    throw AppError.notFound(`文件不存在: ${target.path}`);
  }
  if (stat.isDirectory()) {
    throw AppError.badRequest(ErrorCodes.IS_A_DIRECTORY, `目标是目录，请使用打包下载: ${target.path}`);
  }
  if (!stat.isFile()) {
    throw AppError.badRequest(ErrorCodes.BAD_REQUEST, `不是普通文件，无法下载: ${target.path}`);
  }
  return { target, name: path.basename(target.path), size: stat.size, mtime: stat.mtime };
}

export interface DeleteOutcome {
  deleted: Array<{ path: string; type: EntryType; size: number; recursive: boolean }>;
  failed: Array<{ path: string; code: string; message: string }>;
}

/** 删除文件 / 目录（高危操作，调用方必须已完成 TOTP 校验） */
export async function deleteTargets(
  guard: PathGuard,
  paths: string[],
  options: { recursive: boolean },
): Promise<DeleteOutcome> {
  const outcome: DeleteOutcome = { deleted: [], failed: [] };

  for (const inputPath of paths) {
    let target: ResolvedTarget;
    try {
      target = await guard.resolve(inputPath, { mustExist: true, allowRoot: false });
    } catch (error) {
      if (error instanceof AppError) {
        outcome.failed.push({ path: String(inputPath), code: error.code, message: error.message });
      } else {
        outcome.failed.push({ path: String(inputPath), code: 'ERROR', message: (error as Error).message });
      }
      continue;
    }

    try {
      const linkStat = await fsp.lstat(target.realPath);
      const isDir = linkStat.isDirectory() && !linkStat.isSymbolicLink();
      if (isDir) {
        const children = await fsp.readdir(target.realPath);
        if (children.length > 0 && !options.recursive) {
          outcome.failed.push({
            path: target.path,
            code: ErrorCodes.DIRECTORY_NOT_EMPTY,
            message: '目录非空，需显式设置 recursive=true',
          });
          continue;
        }
        await fsp.rm(target.realPath, { recursive: options.recursive, force: false });
        outcome.deleted.push({ path: target.path, type: 'dir', size: 0, recursive: options.recursive });
      } else {
        const size = linkStat.isFile() ? linkStat.size : 0;
        await fsp.unlink(target.realPath);
        outcome.deleted.push({ path: target.path, type: 'file', size, recursive: false });
      }
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      const code =
        err.code === 'EACCES' || err.code === 'EPERM'
          ? 'PERMISSION_DENIED'
          : err.code === 'ENOTEMPTY'
            ? ErrorCodes.DIRECTORY_NOT_EMPTY
            : err.code === 'ENOENT'
              ? 'ENOENT'
              : (err.code ?? 'ERROR');
      outcome.failed.push({ path: target.path, code, message: err.message ?? String(error) });
    }
  }

  return outcome;
}
