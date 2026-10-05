import { createApp } from './app.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { createContext } from './context.js';
import { StartupError } from './errors.js';
import { createLogger, type Logger } from './logger.js';
import { readVersion, SERVICE_NAME } from './version.js';

async function main(): Promise<void> {
  let config: Config;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      // 启动失败：把配置问题打印清楚，便于 docker logs 排查
      process.stderr.write(`${error.message}\n`);
      process.stderr.write('请参考 .env.example 配置环境变量后重试。\n');
      process.exit(1);
    }
    throw error;
  }

  const logger = createLogger({ level: config.logLevel, base: { service: SERVICE_NAME } });
  return startServer(config, logger);
}

async function startServer(config: Config, logger: Logger): Promise<void> {
  if (config.jwtSecretGenerated) {
    logger.warn('未设置 JWT_SECRET，已随机生成临时密钥：进程重启后需要重新登录（生产环境请显式设置）');
  }
  for (const skipped of config.skippedRoots) {
    logger.warn('已跳过不可用的授权目录（宿主机路径是否挂载到了容器内该路径？）', skipped);
  }

  let ctx;
  try {
    ctx = await createContext(config, logger);
  } catch (error) {
    if (error instanceof StartupError) {
      // 启动期环境问题：直接打到 stderr 并退出，避免容器「看起来在跑但功能全废」
      process.stderr.write(`\n启动失败: ${error.message}\n`);
      for (const line of error.advice) process.stderr.write(`${line}\n`);
      process.stderr.write('\n');
      process.exit(1);
    }
    throw error;
  }
  const app = createApp(ctx);

  const server = app.listen(config.port, config.host);
  server.on('error', (error: NodeJS.ErrnoException) => {
    logger.error('服务启动失败', { error, host: config.host, port: config.port });
    process.exit(1);
  });
  server.on('listening', () => {
    const totpState = '（启动后进行 /api/totp/status 查询）';
    logger.info('文件管理服务已启动', {
      version: readVersion(),
      url: `http://${config.host}:${config.port}`,
      node: process.version,
      allowedRoots: config.allowedRoots,
      dataDir: config.dataDir,
      adminUsername: config.adminUsername,
      jwtTtlSeconds: config.jwtTtlSeconds,
      totp: totpState,
    });
    logger.info('提示：TOTP 绑定后如需重置，只能在服务器上执行命令', {
      command: 'node dist/cli/totp.js reset',
    });
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('收到退出信号，正在停止服务', { signal });
    const force = setTimeout(() => {
      logger.warn('等待连接关闭超时，强制退出');
      process.exit(1);
    }, 10_000);
    force.unref();
    server.close(() => {
      void ctx.audit.flush().finally(() => {
        logger.info('服务已停止');
        process.exit(0);
      });
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (reason) => {
    logger.error('未处理的 Promise 拒绝', { reason });
  });
  process.on('uncaughtException', (error) => {
    logger.error('未捕获异常，进程退出', { error });
    process.exit(1);
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`启动失败: ${(error as Error).stack ?? String(error)}\n`);
  process.exit(1);
});
