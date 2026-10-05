import { hashPassword, verifyScryptHash } from '../services/passwords.js';

const USAGE = `生成 ADMIN_PASSWORD_HASH（scrypt）

用法:
  node dist/cli/hash-password.js '你的密码'
  ADMIN_PASSWORD=你的密码 node dist/cli/hash-password.js

生成的哈希可直接写入环境变量（注意 $ 在 shell / compose 中的转义）:
  ADMIN_PASSWORD_HASH=scrypt$16384$8$1$....$....
`;

async function main(): Promise<number> {
  const password = process.argv[2] ?? process.env['ADMIN_PASSWORD'];
  if (!password) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (password.length < 8) {
    process.stderr.write('警告: 密码长度小于 8 位，建议使用更长的随机密码。\n');
  }
  const hash = await hashPassword(password);
  const ok = await verifyScryptHash(password, hash);
  if (!ok) {
    process.stderr.write('内部错误: 生成的哈希自校验失败。\n');
    return 1;
  }
  process.stdout.write(`${hash}\n`);
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    process.stderr.write(`执行失败: ${(error as Error).stack ?? String(error)}\n`);
    process.exit(1);
  });
