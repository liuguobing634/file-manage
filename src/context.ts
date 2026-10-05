import path from 'node:path';
import type { Config } from './config.js';
import { StartupError } from './errors.js';
import { createLogger, type Logger } from './logger.js';
import { AuditLog } from './services/audit.js';
import {
  collectRootProblems,
  describeRoot,
  identityText,
  permissionAdvice,
  probeWritableDir,
} from './services/diagnostics.js';
import { PathGuard } from './services/pathGuard.js';
import type { CredentialSource } from './services/passwords.js';
import { JsonStore } from './services/store.js';
import { TokenService } from './services/tokens.js';
import { TotpService, totpDefaults, type TotpState } from './services/totpService.js';

export interface AppContext {
  config: Config;
  logger: Logger;
  guard: PathGuard;
  totp: TotpService;
  tokens: TokenService;
  audit: AuditLog;
  credentials: CredentialSource;
  startedAt: number;
}

export function createTotpService(config: Config): TotpService {
  const store = new JsonStore<TotpState>(path.join(config.dataDir, 'totp.json'), totpDefaults);
  return new TotpService(store, config.totp, config.adminUsername);
}

/**
 * 检查数据目录可写性：TOTP 密钥与审计日志都要落盘，
 * 不可写时直接启动失败（否则表现为 TOTP 绑定 500，很难定位）。
 */
export async function assertDataDirWritable(dataDir: string): Promise<void> {
  const probe = await probeWritableDir(dataDir);
  if (probe.ok) return;
  throw new StartupError(
    `无法写入数据目录 ${dataDir}: ${probe.code ?? ''} ${probe.message ?? ''}`.trim(),
    [
      'TOTP 密钥与审计日志必须写入该目录（DATA_DIR）。',
      'Docker 场景常见原因是把宿主目录 bind mount 到了 /var/lib/file-manage，而该目录对容器用户不可写。',
      `注意：下面命令里的 ${dataDir} 是容器内路径，请在宿主机上对「挂载来源的那个宿主目录」执行。`,
      ...permissionAdvice(dataDir, 'write'),
      '  5) 最省事的做法是改用命名卷（由 Docker 初始化好属主）:',
      '     volumes: [ "file-manage-state:/var/lib/file-manage" ]',
    ],
  );
}

/** 组装运行时依赖（server 与测试共用） */
export async function createContext(config: Config, logger?: Logger): Promise<AppContext> {
  const log = logger ?? createLogger({ level: config.logLevel, base: { service: 'file-manage' } });
  await assertDataDirWritable(config.dataDir);

  const guard = new PathGuard(config.allowedRoots, { denyRealPaths: [config.dataDir] });
  const totp = createTotpService(config);
  const tokens = new TokenService(config.jwtSecret, config.jwtTtlSeconds);
  const audit = new AuditLog(path.join(config.dataDir, 'audit.log'), log);
  const credentials: CredentialSource = {
    ...(config.adminPasswordHash ? { passwordHash: config.adminPasswordHash } : {}),
    ...(config.adminPassword ? { password: config.adminPassword } : {}),
  };

  // 启动时逐个体检授权目录，把「不可读/不可写」的原因直接写进日志，
  // 免得跑到界面上才发现挂载目录读不了。
  const roots = await guard.rootsInfo();
  log.info('授权目录检查', {
    runningAs: identityText(),
    dataDir: config.dataDir,
    roots: roots.map((root) => describeRoot(root)),
  });
  for (const problem of collectRootProblems(roots)) {
    log.warn(`授权目录问题: ${problem.path}`, { kind: problem.kind, detail: problem.detail });
  }
  const unreadable = roots.filter((root) => root.exists && (!root.readable || !root.traversable));
  if (unreadable.length > 0) {
    for (const line of permissionAdvice(unreadable[0]!.path, 'read')) log.warn(line);
  }

  return { config, logger: log, guard, totp, tokens, audit, credentials, startedAt: Date.now() };
}
