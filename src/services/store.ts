import fs from 'node:fs/promises';
import path from 'node:path';
import { AppError } from '../errors.js';

/**
 * 极简 JSON 文件存储：进程内缓存 + 串行化写入 + 原子替换 + 0600 权限。
 * 用于保存 TOTP 密钥这类必须持久化、且不能出现并发写坏的小状态。
 *
 * 缓存带「文件指纹」校验：命令行工具（另一个进程）重置 / 修改状态文件后，
 * 正在运行的服务能在下一次读取时立即感知，无需重启。
 */
export class JsonStore<T extends Record<string, unknown>> {
  private cache: T | undefined;
  /** 缓存对应的文件指纹（mtimeMs:size），文件不存在时为 null */
  private cacheStamp: string | null = null;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly file: string,
    private readonly defaults: T | (() => T),
  ) {}

  get filePath(): string {
    return this.file;
  }

  private defaultsValue(): T {
    if (typeof this.defaults === 'function') return (this.defaults as () => T)();
    return structuredClone(this.defaults);
  }

  /** 文件指纹；不存在或不可读时返回 null */
  private async stamp(): Promise<string | null> {
    try {
      const stat = await fs.stat(this.file);
      return `${stat.mtimeMs}:${stat.size}`;
    } catch {
      return null;
    }
  }

  async read(): Promise<T> {
    const stamp = await this.stamp();
    if (this.cache !== undefined && stamp === this.cacheStamp) return this.cache;
    this.cache = await this.loadFromDisk();
    this.cacheStamp = stamp;
    return this.cache;
  }

  private async loadFromDisk(): Promise<T> {
    let text: string;
    try {
      text = await fs.readFile(this.file, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return this.defaultsValue();
      throw AppError.internal(`读取状态文件失败: ${this.file}`, error);
    }
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('内容不是 JSON 对象');
      return { ...this.defaultsValue(), ...(parsed as T) };
    } catch (error) {
      throw AppError.internal(
        `状态文件已损坏，无法解析: ${this.file}（请修复或删除后重启，TOTP 需重新绑定）: ${(error as Error).message}`,
      );
    }
  }

  /** 串行化的读-改-写。mutator 抛错时不会落盘。 */
  async update(mutator: (current: T) => T | Promise<T>): Promise<T> {
    const run = async (): Promise<T> => {
      const current = await this.read();
      const next = await mutator(current);
      await this.write(next);
      this.cache = next;
      this.cacheStamp = await this.stamp();
      return next;
    };
    const promise = this.queue.then(run, run);
    this.queue = promise.then(
      () => undefined,
      () => undefined,
    );
    return promise;
  }

  async write(value: T): Promise<void> {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.${Date.now()}.tmp`;
    const handle = await fs.open(tmp, 'w', 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, this.file);
    try {
      await fs.chmod(this.file, 0o600);
    } catch {
      /* Windows 等平台可能不支持，忽略 */
    }
  }

  /** 删除状态文件（TOTP 重置使用） */
  async reset(): Promise<void> {
    const run = async (): Promise<void> => {
      try {
        await fs.unlink(this.file);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      this.cache = this.defaultsValue();
      this.cacheStamp = null;
    };
    const promise = this.queue.then(run, run);
    this.queue = promise.then(
      () => undefined,
      () => undefined,
    );
    return promise;
  }

  invalidate(): void {
    this.cache = undefined;
    this.cacheStamp = null;
  }
}
