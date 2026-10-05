import path from 'node:path';
import { Router, type Response } from 'express';
import type { AppContext } from '../context.js';
import { AppError, ErrorCodes, isAppError } from '../errors.js';
import { requireAuth } from '../middleware/auth.js';
import { RateLimiter, ipUserKey, rateLimitMiddleware } from '../middleware/rateLimit.js';
import {
  collectFiles,
  deleteTargets,
  listDirectory,
  normalizeExtensions,
  resolveDownloadFile,
  type ListOptions,
} from '../services/fileService.js';
import type { ResolvedTarget } from '../services/pathGuard.js';
import { streamZip } from '../services/zip.js';
import { asyncHandler, clientIp, contentDisposition } from '../utils/http.js';
import {
  asObject,
  optBool,
  optInt,
  optString,
  optStringArray,
  type Source,
} from '../utils/validate.js';
import { reqString, reqStringArray } from '../utils/validate.js';

const ROOTS_MAGIC = new Set(['@roots', '@all']);
/** 单次请求允许的最大路径字符串长度 */
const MAX_PATH_LENGTH = 4096;
const MAX_PATHS_PER_REQUEST = 1000;

function resolvePaths(guard: { allowedRoots: string[] }, input: string[]): string[] {
  const out: string[] = [];
  for (const item of input) {
    if (ROOTS_MAGIC.has(item.toLowerCase())) out.push(...guard.allowedRoots);
    else out.push(item);
  }
  return [...new Set(out)];
}

function buildListOptions(
  ctx: AppContext,
  source: Source,
  paths: string[],
  defaults: { recursive: boolean },
): ListOptions {
  const config = ctx.config;
  return {
    paths,
    recursive: optBool(source, 'recursive', defaults.recursive),
    maxDepth: optInt(source, 'maxDepth', { def: 0, min: 0, max: config.maxListDepth }),
    includeDirs: optBool(source, 'includeDirs', false),
    showHidden: optBool(source, 'showHidden', false),
    extensions: normalizeExtensions(optStringArray(source, 'extensions', { max: 64, maxLength: 32 })),
    nameContains: optString(source, 'nameContains', { maxLength: 200 }),
    minSize: optInt(source, 'minSize', { def: 0, min: 0 }),
    maxSize: optInt(source, 'maxSize', { def: 0, min: 0 }),
    limit: optInt(source, 'limit', { def: config.maxListFiles, min: 1, max: config.maxListFiles }),
    maxDepthLimit: config.maxListDepth,
  };
}

function computeParent(target: ResolvedTarget): string | null {
  if (target.isRoot) return null;
  const parent = path.dirname(target.path);
  return parent === target.path ? null : parent;
}

/** 单文件下载：交给 express 的 sendFile（自带 Content-Type / Range / ETag 支持） */
function sendFileAsync(res: Response, target: ResolvedTarget, name: string): Promise<void> {
  res.setHeader('Content-Disposition', contentDisposition(name));
  res.setHeader('Cache-Control', 'no-store');
  return new Promise<void>((resolve, reject) => {
    res.sendFile(
      target.realPath,
      { dotfiles: 'allow', acceptRanges: true, cacheControl: false, etag: true },
      (error?: Error | null) => {
        if (error) reject(error);
        else resolve();
      },
    );
  });
}

export function createFilesRouter(ctx: AppContext, deps: { zipStreamer?: typeof streamZip } = {}): Router {
  const router = Router();
  const auth = requireAuth(ctx.tokens);
  const authForDownload = requireAuth(ctx.tokens, { allowQueryToken: true });
  const zipStreamer = deps.zipStreamer ?? streamZip;
  const totpLimiter = new RateLimiter({
    ...ctx.config.totpRate,
    message: '二次验证尝试过于频繁，请稍后再试',
  });

  /** GET /api/roots —— 启动时配置的多个根目录 */
  router.get(
    '/roots',
    auth,
    asyncHandler(async (_req, res) => {
      res.json({ roots: await ctx.guard.rootsInfo() });
    }),
  );

  /** GET /api/browse?path=/data —— 浏览单个目录 */
  router.get(
    '/browse',
    auth,
    asyncHandler(async (req, res) => {
      const query = req.query as Source;
      const inputPath = optString(query, 'path', { maxLength: MAX_PATH_LENGTH });
      const showHidden = optBool(query, 'showHidden', false);
      const limit = optInt(query, 'limit', { def: ctx.config.maxListFiles, min: 1, max: ctx.config.maxListFiles });

      if (inputPath === undefined) {
        const roots = await ctx.guard.rootsInfo();
        const entries = roots
          .filter((root) => root.exists)
          .map((root) => ({
            name: path.basename(root.path) || root.path,
            path: root.path,
            type: 'dir' as const,
            size: 0,
            mtime: null,
            mode: null,
            ext: '',
            isSymlink: false,
            root: root.path,
            relPath: '.',
          }));
        res.json({ path: null, root: null, parent: null, count: entries.length, truncated: false, entries, roots });
        return;
      }

      const listing = await listDirectory(ctx.guard, inputPath, { showHidden, limit });
      ctx.audit.record({
        action: 'browse',
        result: 'success',
        username: req.auth?.username,
        ip: clientIp(req),
        requestId: req.requestId,
        detail: { path: listing.target.path, count: listing.count },
      });
      res.json({
        path: listing.target.path,
        root: listing.target.root,
        parent: computeParent(listing.target),
        count: listing.count,
        truncated: listing.truncated,
        entries: listing.entries,
      });
    }),
  );

  const listHandler = asyncHandler(async (req, res) => {
    const query = req.query as Source;
    const body = req.method === 'POST' ? asObject(req.body ?? {}) : {};
    const source: Source = { ...query, ...body };

    let rawPaths: string[];
    if (req.method === 'GET') {
      const single = optString(query, 'path', { maxLength: MAX_PATH_LENGTH });
      const multi = optStringArray(query, 'paths', {
        max: MAX_PATHS_PER_REQUEST,
        maxLength: MAX_PATH_LENGTH,
        splitComma: true,
      });
      rawPaths = single === undefined ? multi : [single, ...multi];
      if (rawPaths.length === 0) {
        throw AppError.badRequest(ErrorCodes.BAD_REQUEST, '缺少必填参数 path（或 paths）');
      }
    } else {
      rawPaths = reqStringArray(body, 'paths', { max: MAX_PATHS_PER_REQUEST, maxLength: MAX_PATH_LENGTH });
    }

    const paths = resolvePaths(ctx.guard, rawPaths);
    const options = buildListOptions(ctx, source, paths, { recursive: false });
    const result = await collectFiles(ctx.guard, options);
    ctx.audit.record({
      action: 'list',
      result: 'success',
      username: req.auth?.username,
      ip: clientIp(req),
      requestId: req.requestId,
      detail: {
        paths,
        recursive: options.recursive,
        count: result.count,
        truncated: result.truncated,
        errors: result.errors.length,
      },
    });
    res.json(result);
  });

  /** GET /api/files?path=/data&recursive=true —— 单路径便捷列举 */
  router.get('/files', auth, listHandler);
  /** POST /api/files/list —— 多目录列举 */
  router.post('/files/list', auth, listHandler);

  /** GET /api/files/download?path=/data/app.log —— 下载单个文件 */
  router.get(
    '/files/download',
    authForDownload,
    asyncHandler(async (req, res) => {
      const query = req.query as Source;
      const inputPath = reqString(query, 'path', { maxLength: MAX_PATH_LENGTH });
      const file = await resolveDownloadFile(ctx.guard, inputPath);
      ctx.audit.record({
        action: 'download',
        result: 'success',
        username: req.auth?.username,
        ip: clientIp(req),
        requestId: req.requestId,
        detail: { path: file.target.path, size: file.size, mode: 'single' },
      });
      await sendFileAsync(res, file.target, file.name);
    }),
  );

  /** POST /api/files/download —— 多选打包下载（zip） */
  router.post(
    '/files/download',
    auth,
    asyncHandler(async (req, res) => {
      const body = asObject(req.body ?? {});
      const paths = resolvePaths(
        ctx.guard,
        reqStringArray(body, 'paths', { max: MAX_PATHS_PER_REQUEST, maxLength: MAX_PATH_LENGTH }),
      );
      const options = buildListOptions(ctx, body, paths, { recursive: true });
      const result = await collectFiles(ctx.guard, options);

      if (result.files.length === 0) {
        throw AppError.notFound('没有可下载的文件', { errors: result.errors });
      }
      if (result.files.length > ctx.config.maxZipFiles) {
        throw AppError.badRequest(
          'TOO_MANY_FILES',
          `文件数量超过打包上限（${ctx.config.maxZipFiles}），请缩小范围或使用筛选条件`,
          { count: result.files.length },
        );
      }

      ctx.audit.record({
        action: 'download',
        result: 'success',
        username: req.auth?.username,
        ip: clientIp(req),
        requestId: req.requestId,
        detail: { mode: 'zip', count: result.files.length, totalSize: result.totalSize },
      });

      const only = result.files[0];
      if (result.files.length === 1 && only && only.type === 'file') {
        const file = await resolveDownloadFile(ctx.guard, only.path);
        await sendFileAsync(res, file.target, file.name);
        return;
      }
      await zipStreamer(res, result.files);
    }),
  );

  const deleteHandler = asyncHandler(async (req, res) => {
    const source: Source =
      req.method === 'POST' ? asObject(req.body ?? {}) : ((req.body ?? {}) as Source);
    const paths = resolvePaths(
      ctx.guard,
      reqStringArray(source, 'paths', { max: ctx.config.maxDeletePaths, maxLength: MAX_PATH_LENGTH }),
    );
    const recursive = optBool(source, 'recursive', false);

    const rawCode = source['totp'] ?? source['code'] ?? source['totpCode'];
    if (rawCode === undefined || rawCode === null || String(rawCode).trim() === '') {
      throw AppError.badRequest(
        ErrorCodes.TOTP_REQUIRED,
        '高危操作（删除）必须在请求参数中携带 TOTP 二次验证码：{"totp":"123456"}',
      );
    }
    const code = String(Array.isArray(rawCode) ? rawCode[0] : rawCode).trim();
    if (!/^\d{4,10}$/.test(code)) {
      throw AppError.badRequest(ErrorCodes.TOTP_REQUIRED, '二次验证码格式不正确（应为数字）');
    }

    const key = ipUserKey(req);
    try {
      await ctx.totp.consume(code);
    } catch (error) {
      if (isAppError(error) && error.code === ErrorCodes.TOTP_INVALID) {
        totpLimiter.record(key);
        ctx.audit.record({
          action: 'delete',
          result: 'failure',
          username: req.auth?.username,
          ip: clientIp(req),
          requestId: req.requestId,
          detail: { reason: 'totp_invalid', paths },
        });
      }
      throw error;
    }

    const outcome = await deleteTargets(ctx.guard, paths, { recursive });
    ctx.audit.record({
      action: 'delete',
      result: outcome.failed.length === 0 ? 'success' : 'failure',
      username: req.auth?.username,
      ip: clientIp(req),
      requestId: req.requestId,
      detail: {
        recursive,
        deleted: outcome.deleted.map((item) => item.path),
        failed: outcome.failed,
      },
    });
    res.json({ count: outcome.deleted.length, deleted: outcome.deleted, failed: outcome.failed });
  });

  /** 高危操作：删除（POST 与 DELETE 两种写法都支持，语义一致） */
  router.post(
    '/files/delete',
    auth,
    rateLimitMiddleware(totpLimiter, ipUserKey, '二次验证尝试过于频繁，请稍后再试'),
    deleteHandler,
  );
  router.delete(
    '/files',
    auth,
    rateLimitMiddleware(totpLimiter, ipUserKey, '二次验证尝试过于频繁，请稍后再试'),
    deleteHandler,
  );

  return router;
}
