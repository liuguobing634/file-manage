import { ConfigError, loadConfig } from '../config.js';
import { StartupError } from '../errors.js';
import {
  collectRootProblems,
  describeRoot,
  identityText,
  permissionAdvice,
  probeWritableDir,
} from '../services/diagnostics.js';
import { PathGuard } from '../services/pathGuard.js';

const USAGE = `file-manage 环境体检（容器里排查「挂载目录不可读 / 不可写」用这个）

用法:
  node dist/cli/doctor.js

它会打印:
  - 当前进程身份（容器里通常是 uid=1000 的 node）
  - DATA_DIR 是否可写（TOTP 密钥与审计日志要落盘）
  - ALLOWED_ROOTS 里每个目录的存在性、属主、权限位、R/W/X
  - 每个问题的具体修复命令；有阻塞问题时退出码为 1

Docker 用法:
  docker exec -it file-manage node dist/cli/doctor.js
`;

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }

  let config;
  try {
    config = loadConfig({ requireAuth: false });
  } catch (error) {
    if (error instanceof ConfigError) {
      process.stderr.write(`${error.message}\n`);
      return 1;
    }
    throw error;
  }

  const lines: string[] = [];
  let blocking = 0;

  lines.push('== file-manage 环境体检 ==');
  lines.push(`进程身份   : ${identityText()}`);
  lines.push(`Node / 平台: ${process.version} / ${process.platform}`);
  lines.push(`工作目录   : ${process.cwd()}`);
  lines.push('');

  lines.push('== 数据目录（TOTP 密钥 / 审计日志）==');
  const dataProbe = await probeWritableDir(config.dataDir);
  if (dataProbe.ok) {
    lines.push(`OK   ${config.dataDir} 可写`);
  } else {
    blocking += 1;
    lines.push(`FAIL ${config.dataDir} 不可写: ${dataProbe.code ?? ''} ${dataProbe.message ?? ''}`.trim());
    for (const line of permissionAdvice(config.dataDir, 'write')) lines.push(line);
  }
  lines.push('');

  lines.push('== 授权目录 ALLOWED_ROOTS ==');
  if (config.allowedRoots.length === 0) {
    blocking += 1;
    lines.push('FAIL 没有可用的授权目录（ALLOWED_ROOTS 未设置，或配置的目录在容器内不存在）');
    lines.push('     Docker 场景注意写容器内路径，例如宿主机 /data/backups 挂到 /data/backups 时，');
    lines.push('     ALLOWED_ROOTS 要写成 /data 或 /data/backups，而不是宿主机上的其它路径。');
  } else {
    const guard = new PathGuard(config.allowedRoots, { denyRealPaths: [config.dataDir] });
    const roots = await guard.rootsInfo();
    for (const root of roots) lines.push(`     ${describeRoot(root)}`);

    for (const problem of collectRootProblems(roots)) {
      if (problem.kind === 'unwritable') {
        lines.push(`WARN ${problem.path}: ${problem.detail}`);
      } else {
        blocking += 1;
        lines.push(`FAIL ${problem.path}: ${problem.detail}`);
      }
    }
    const unreadable = roots.filter((root) => root.exists && (!root.readable || !root.traversable));
    if (unreadable.length > 0) {
      lines.push('');
      for (const line of permissionAdvice(unreadable[0]!.path, 'read')) lines.push(line);
    }
  }
  lines.push('');

  if (config.skippedRoots.length > 0) {
    lines.push('== 被跳过的授权目录（启动时未生效）==');
    for (const skipped of config.skippedRoots) {
      lines.push(`WARN ${skipped.path}: ${skipped.reason}`);
    }
    lines.push('     多半是宿主机目录没有挂载到容器内的这个路径，或路径写错了。');
    lines.push('');
  }

  lines.push('提示: 容器内 uid 1000 = 镜像里的 node 用户；');
  lines.push('      想让宿主机目录对它可读写: chown -R 1000:1000 <宿主目录>');
  lines.push('      或让容器用 root 运行: 在 compose 的服务里加 user: "0:0"');
  lines.push('      RHEL/CentOS 系还要注意 SELinux，挂载可加 :z / :Z');

  process.stdout.write(`${lines.join('\n')}\n`);
  if (blocking > 0) {
    process.stdout.write(`\n发现 ${blocking} 个阻塞问题，服务可能无法正常使用。\n`);
    return 1;
  }
  process.stdout.write('\n未发现阻塞问题。\n');
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    if (error instanceof StartupError) {
      process.stderr.write(`${error.message}\n${error.advice.join('\n')}\n`);
      process.exit(1);
    }
    process.stderr.write(`执行失败: ${(error as Error).stack ?? String(error)}\n`);
    process.exit(1);
  });
