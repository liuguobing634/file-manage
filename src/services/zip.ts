import path from 'node:path';
import archiver from 'archiver';
import type { Response } from 'express';
import { contentDisposition, timestampSuffix } from '../utils/http.js';
import type { FileEntry } from './fileService.js';

/** zip 内的条目名：以根目录名作为顶层目录，避免多选时重名覆盖 */
export function archiveEntryName(entry: FileEntry): string {
  const rootName = path.basename(entry.root) || 'root';
  if (entry.relPath === '.' || entry.relPath === '') return rootName;
  return `${rootName}/${entry.relPath}`.split(path.sep).join('/');
}

export interface StreamZipOptions {
  filename?: string;
}

/**
 * 把文件列表以 zip 流式写入响应。
 * 注意：调用前必须已经完成路径校验与文件收集，以便错误能以 JSON 返回。
 */
export async function streamZip(res: Response, files: FileEntry[], options: StreamZipOptions = {}): Promise<void> {
  const filename = options.filename ?? `files-${timestampSuffix()}.zip`;
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', contentDisposition(filename));
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Accel-Buffering', 'no');

  const archive = archiver('zip', { zlib: { level: 6 } });

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const succeed = (): void => {
      if (settled) return;
      settled = true;
      resolve();
    };

    archive.on('error', fail);
    archive.on('warning', (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return;
      fail(error);
    });
    archive.on('end', succeed);
    res.on('close', () => {
      if (!res.writableEnded) {
        archive.abort();
        succeed();
      }
    });

    archive.pipe(res);
    for (const file of files) {
      archive.file(file.path, { name: archiveEntryName(file) });
    }
    archive.finalize().catch(fail);
  });
}
