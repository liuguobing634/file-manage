import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/**
 * 读取 package.json 的版本号。
 * 注意：本文件必须位于 src/ 根目录，这样编译到 dist/ 后 `../package.json` 才指向项目根目录。
 */
export function readVersion(): string {
  try {
    const pkg = require('../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const SERVICE_NAME = 'file-manage';
