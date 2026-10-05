import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  base32Decode,
  base32Encode,
  buildOtpAuthUrl,
  counterFor,
  generateSecret,
  hotp,
  totpAt,
  verifyTotp,
} from '../src/services/totp.js';

describe('Base32 (RFC 4648)', () => {
  test('编码 / 解码可往返', () => {
    const cases = ['f', 'fo', 'foo', 'foob', 'fooba', 'foobar', '12345678901234567890'];
    for (const item of cases) {
      const buffer = Buffer.from(item, 'ascii');
      assert.deepEqual(base32Decode(base32Encode(buffer)), buffer);
    }
    const random = Buffer.from(Array.from({ length: 33 }, (_, index) => (index * 37) % 256));
    assert.deepEqual(base32Decode(base32Encode(random)), random);
  });

  test('已知向量', () => {
    assert.equal(base32Encode(Buffer.from('foobar', 'ascii')), 'MZXW6YTBOI');
    assert.equal(base32Encode(Buffer.from('f', 'ascii')), 'MY');
    assert.equal(base32Decode('MZXW6YTBOI======').toString('ascii'), 'foobar');
    assert.equal(base32Decode('mzxw6ytboi').toString('ascii'), 'foobar');
  });

  test('非法字符报错', () => {
    assert.throws(() => base32Decode('MZXW6YTBO1'), /非法 Base32 字符/);
    assert.throws(() => base32Decode(''), /为空/);
  });

  test('生成的密钥是合法的 Base32 且长度符合预期', () => {
    const secret = generateSecret();
    assert.match(secret, /^[A-Z2-7]+$/);
    assert.equal(base32Decode(secret).length, 20);
  });
});

describe('HOTP (RFC 4226 附录 D)', () => {
  const secret = Buffer.from('12345678901234567890', 'ascii');
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

  test('计数器 0-9 的数值与 RFC 一致', () => {
    expected.forEach((code, counter) => {
      assert.equal(hotp(secret, counter), code, `counter=${counter}`);
    });
  });
});

describe('TOTP (RFC 6238 附录 B)', () => {
  const sha1Secret = Buffer.from('12345678901234567890', 'ascii');
  const sha256Secret = Buffer.from('12345678901234567890123456789012', 'ascii');
  const sha512Secret = Buffer.from(
    '1234567890123456789012345678901234567890123456789012345678901234',
    'ascii',
  );

  const vectors: Array<{ time: number; sha1: string; sha256: string; sha512: string }> = [
    { time: 59, sha1: '94287082', sha256: '46119246', sha512: '90693936' },
    { time: 1111111109, sha1: '07081804', sha256: '68084774', sha512: '25091201' },
    { time: 1111111111, sha1: '14050471', sha256: '67062674', sha512: '99943326' },
    { time: 1234567890, sha1: '89005924', sha256: '91819424', sha512: '93441116' },
    { time: 2000000000, sha1: '69279037', sha256: '90698825', sha512: '38618901' },
    { time: 20000000000, sha1: '65353130', sha256: '77737706', sha512: '47863826' },
  ];

  test('SHA1 / SHA256 / SHA512 与 RFC 一致（8 位）', () => {
    for (const vector of vectors) {
      const timeMs = vector.time * 1000;
      assert.equal(totpAt(sha1Secret, timeMs, { digits: 8, period: 30, algorithm: 'sha1' }).code, vector.sha1);
      assert.equal(totpAt(sha256Secret, timeMs, { digits: 8, period: 30, algorithm: 'sha256' }).code, vector.sha256);
      assert.equal(totpAt(sha512Secret, timeMs, { digits: 8, period: 30, algorithm: 'sha512' }).code, vector.sha512);
    }
  });

  test('counter 计算与周期相关', () => {
    assert.equal(counterFor(59_000, 30), 1);
    assert.equal(counterFor(60_000, 30), 2);
    assert.equal(counterFor(0, 30), 0);
  });
});

describe('verifyTotp', () => {
  const secret = generateSecret();
  const params = { digits: 6, period: 30, algorithm: 'sha1' as const };
  const now = 1_700_000_000_000;

  test('接受当前 / 相邻周期，拒绝过期周期', () => {
    const current = totpAt(base32Decode(secret), now, params).code;
    assert.equal(verifyTotp(secret, current, { ...params, window: 1, now }).valid, true);

    const previous = totpAt(base32Decode(secret), now - 30_000, params).code;
    assert.equal(verifyTotp(secret, previous, { ...params, window: 1, now }).valid, true);

    const far = totpAt(base32Decode(secret), now - 5 * 30_000, params).code;
    assert.equal(verifyTotp(secret, far, { ...params, window: 1, now }).valid, false);
  });

  test('拒绝错误格式与错误验证码', () => {
    assert.equal(verifyTotp(secret, '12345', { ...params, now }).valid, false);
    assert.equal(verifyTotp(secret, 'abcdef', { ...params, now }).valid, false);
    assert.equal(verifyTotp(secret, '000000', { ...params, now }).valid, false);
  });

  test('minStepExclusive 阻止同一验证码重放，但允许更新的周期', () => {
    const step = counterFor(now, 30);
    const current = totpAt(base32Decode(secret), now, params).code;
    const first = verifyTotp(secret, current, { ...params, now, minStepExclusive: null });
    assert.equal(first.valid, true);
    assert.equal(first.step, step);

    const replay = verifyTotp(secret, current, { ...params, now, minStepExclusive: first.step });
    assert.equal(replay.valid, false);

    const next = totpAt(base32Decode(secret), now + 30_000, params).code;
    const after = verifyTotp(secret, next, { ...params, window: 1, now, minStepExclusive: first.step });
    assert.equal(after.valid, true);
    assert.equal(after.step, step + 1);
  });
});

describe('otpauth URL', () => {
  test('包含全部参数且标签正确编码', () => {
    const url = buildOtpAuthUrl({
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'file-manage',
      account: 'admin',
      digits: 6,
      period: 30,
      algorithm: 'sha1',
    });
    assert.match(url, /^otpauth:\/\/totp\/file-manage:admin\?/);
    const parsed = new URL(url);
    assert.equal(parsed.searchParams.get('secret'), 'JBSWY3DPEHPK3PXP');
    assert.equal(parsed.searchParams.get('issuer'), 'file-manage');
    assert.equal(parsed.searchParams.get('digits'), '6');
    assert.equal(parsed.searchParams.get('period'), '30');
    assert.equal(parsed.searchParams.get('algorithm'), 'SHA1');
  });
});
