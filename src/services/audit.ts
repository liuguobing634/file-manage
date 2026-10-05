import fsp from 'node:fs/promises';
import path from 'node:path';
import type { Logger } from '../logger.js';

export interface AuditEntry {
  action: 'login' | 'login_failed' | 'logout' | 'list' | 'browse' | 'download' | 'delete' | 'totp_setup' | 'totp_activate' | 'totp_failed';
  result: 'success' | 'failure';
  username?: string;
  ip?: string;
  requestId?: string;
  detail?: Record<string, unknown>;
}

/** 运维审计日志（JSON Lines 追加写入，写入串行化且失败不影响主流程） */
export class AuditLog {
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly file: string,
    private readonly logger: Logger,
    private readonly enabled = true,
  ) {}

  get filePath(): string {
    return this.file;
  }

  record(entry: AuditEntry): void {
    if (!this.enabled) return;
    const line = `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`;
    this.queue = this.queue
      .then(async () => {
        await fsp.mkdir(path.dirname(this.file), { recursive: true });
        await fsp.appendFile(this.file, line, { encoding: 'utf8', mode: 0o600 });
      })
      .catch((error: unknown) => {
        this.logger.warn('写入审计日志失败', { error });
      });
  }

  async flush(): Promise<void> {
    await this.queue;
  }
}
