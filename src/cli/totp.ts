import { ConfigError, loadConfig } from '../config.js';
import { createTotpService } from '../context.js';

const USAGE = `file-manage TOTP 管理命令行（TOTP 的重置不提供 HTTP API，只能在本机执行）

用法:
  node dist/cli/totp.js status              查看 TOTP 绑定状态
  node dist/cli/totp.js reset               重置（删除已生成的密钥，之后可重新 setup）
  node dist/cli/totp.js reset --dry-run     只显示将要重置的内容，不实际删除

说明:
  - 该命令只依赖 DATA_DIR / TOTP_* 环境变量；
  - Docker 部署时可在容器内执行: docker exec -it <容器名> node dist/cli/totp.js reset
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const command = argv[0] ?? 'status';
  const flags = new Set(argv.slice(1));

  if (command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(USAGE);
    return 0;
  }

  let dataDir: string;
  let config;
  try {
    config = loadConfig({ requireAuth: false });
    dataDir = config.dataDir;
  } catch (error) {
    if (error instanceof ConfigError) {
      process.stderr.write(`${error.message}\n`);
      return 1;
    }
    throw error;
  }

  const totp = createTotpService(config);

  switch (command) {
    case 'status': {
      const status = await totp.status();
      const lines = [
        `数据目录        : ${dataDir}`,
        `状态文件        : ${totp.stateFile}`,
        `是否已生成密钥  : ${status.configured ? '是' : '否'}`,
        `是否已激活      : ${status.enabled ? '是' : '否'}`,
        `签发者 / 账号   : ${status.issuer} / ${status.account}`,
        `算法 / 位数 / 周期: ${status.algorithm} / ${status.digits} / ${status.period}s`,
        `防重放          : ${status.preventReplay ? '开启' : '关闭'}`,
        `生成时间        : ${status.createdAt ?? '-'}`,
        `激活时间        : ${status.enabledAt ?? '-'}`,
        `成功校验次数    : ${status.usedCount}`,
      ];
      process.stdout.write(`${lines.join('\n')}\n`);
      if (!status.configured) {
        process.stdout.write('提示: 尚未生成密钥，请登录后调用 POST /api/totp/setup 获取二维码。\n');
      } else if (!status.enabled) {
        process.stdout.write('提示: 密钥已生成但未激活，请扫码后调用 POST /api/totp/verify 完成绑定。\n');
      }
      return 0;
    }

    case 'reset': {
      const status = await totp.status();
      if (!status.configured) {
        process.stdout.write('当前没有已生成的 TOTP 密钥，无需重置。\n');
        return 0;
      }
      if (flags.has('--dry-run')) {
        process.stdout.write(
          `[dry-run] 将会删除 ${totp.stateFile}（当前已生成=${status.configured}, 已激活=${status.enabled}）\n`,
        );
        return 0;
      }
      const result = await totp.reset();
      process.stdout.write(
        `已重置 TOTP（删除密钥: ${result.hadSecret ? '是' : '否'}, 之前是否激活: ${result.wasEnabled ? '是' : '否'}）。\n` +
          '请重新登录并调用 POST /api/totp/setup 生成新的二维码。\n',
      );
      return 0;
    }

    default:
      process.stderr.write(`未知命令: ${command}\n\n${USAGE}`);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    process.stderr.write(`执行失败: ${(error as Error).stack ?? String(error)}\n`);
    process.exit(1);
  });
