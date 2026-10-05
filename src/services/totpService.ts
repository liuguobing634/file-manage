import QRCode from 'qrcode';
import type { TotpSettings } from '../config.js';
import { AppError, ErrorCodes } from '../errors.js';
import { JsonStore } from './store.js';
import { buildOtpAuthUrl, generateSecret, verifyTotp, type HmacAlgorithm } from './totp.js';

export interface TotpState extends Record<string, unknown> {
  secret: string | null;
  enabled: boolean;
  createdAt: string | null;
  enabledAt: string | null;
  /** 最近一次成功使用的 step，用于防重放 */
  lastUsedStep: number | null;
  usedCount: number;
  /**
   * 绑定时的参数快照。生成二维码时一并冻结，之后校验一律用它，
   * 这样即使运维改了 TOTP_ALGORITHM / DIGITS / PERIOD，已绑定的验证器也不会失效。
   */
  issuer: string | null;
  account: string | null;
  digits: number | null;
  period: number | null;
  algorithm: string | null;
}

export function totpDefaults(): TotpState {
  return {
    secret: null,
    enabled: false,
    createdAt: null,
    enabledAt: null,
    lastUsedStep: null,
    usedCount: 0,
    issuer: null,
    account: null,
    digits: null,
    period: null,
    algorithm: null,
  };
}

export interface TotpBinding {
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: HmacAlgorithm;
}

export interface TotpStatus {
  configured: boolean;
  enabled: boolean;
  /** 以下 digits / period / algorithm 是**实际用于校验**的参数（已绑定则是绑定时的快照） */
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: string;
  /** 环境变量里的参数与已绑定参数不一致时为 true（改动不会生效，需 reset 后重新绑定） */
  paramsChanged: boolean;
  window: number;
  preventReplay: boolean;
  createdAt: string | null;
  enabledAt: string | null;
  usedCount: number;
}

export interface TotpSetupResult {
  secret: string;
  otpauthUrl: string;
  qrCodeDataUrl: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: string;
  createdAt: string;
}

const RESET_HINT = 'TOTP 已生成，不能重复生成。如需重置请使用命令行（不提供 API）: node dist/cli/totp.js reset';

/**
 * TOTP 生命周期管理：
 * - 只能生成一次（setup），重置仅限命令行；
 * - verify 激活后才允许高危操作；
 * - 高危操作走 consume()，校验与防重放在同一次原子更新内完成；
 * - 参数（算法/位数/周期/签发者）在 setup 时冻结进状态文件，避免改环境变量后绑定失效。
 */
export class TotpService {
  constructor(
    private readonly store: JsonStore<TotpState>,
    private readonly settings: TotpSettings,
    private readonly account: string,
  ) {}

  get stateFile(): string {
    return this.store.filePath;
  }

  private settingsBinding(): TotpBinding {
    return {
      issuer: this.settings.issuer,
      account: this.account,
      digits: this.settings.digits,
      period: this.settings.period,
      algorithm: this.settings.algorithm.toLowerCase() as HmacAlgorithm,
    };
  }

  /** 已绑定就用绑定快照，否则用当前环境变量配置 */
  private bindingOf(state: TotpState): TotpBinding {
    const fallback = this.settingsBinding();
    if (!state.secret) return fallback;
    return {
      issuer: state.issuer ?? fallback.issuer,
      account: state.account ?? fallback.account,
      digits: state.digits ?? fallback.digits,
      period: state.period ?? fallback.period,
      algorithm: (state.algorithm?.toLowerCase() as HmacAlgorithm | undefined) ?? fallback.algorithm,
    };
  }

  private otpauthUrl(secret: string, binding: TotpBinding): string {
    return buildOtpAuthUrl({
      secret,
      issuer: binding.issuer,
      account: binding.account,
      digits: binding.digits,
      period: binding.period,
      algorithm: binding.algorithm,
    });
  }

  async status(): Promise<TotpStatus> {
    const state = await this.store.read();
    const binding = this.bindingOf(state);
    const settings = this.settingsBinding();
    return {
      configured: state.secret !== null,
      enabled: state.secret !== null && state.enabled,
      issuer: binding.issuer,
      account: binding.account,
      digits: binding.digits,
      period: binding.period,
      algorithm: binding.algorithm.toUpperCase(),
      paramsChanged:
        state.secret !== null &&
        (binding.digits !== settings.digits ||
          binding.period !== settings.period ||
          binding.algorithm !== settings.algorithm),
      window: this.settings.window,
      preventReplay: this.settings.preventReplay,
      createdAt: state.createdAt,
      enabledAt: state.enabledAt,
      usedCount: state.usedCount,
    };
  }

  /** 生成密钥 + 二维码（一次性），并把参数快照写入状态文件 */
  async setup(): Promise<TotpSetupResult> {
    const secret = generateSecret();
    const createdAt = new Date().toISOString();
    const binding = this.settingsBinding();
    const updated = await this.store.update((current) => {
      if (current.secret) {
        throw AppError.conflict(ErrorCodes.TOTP_ALREADY_CONFIGURED, RESET_HINT);
      }
      return {
        ...current,
        secret,
        enabled: false,
        createdAt,
        enabledAt: null,
        lastUsedStep: null,
        issuer: binding.issuer,
        account: binding.account,
        digits: binding.digits,
        period: binding.period,
        algorithm: binding.algorithm,
      };
    });
    const storedSecret = updated.secret ?? secret;
    const effective = this.bindingOf(updated);
    const otpauthUrl = this.otpauthUrl(storedSecret, effective);
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 320,
    });
    return {
      secret: storedSecret,
      otpauthUrl,
      qrCodeDataUrl,
      issuer: effective.issuer,
      account: effective.account,
      digits: effective.digits,
      period: effective.period,
      algorithm: effective.algorithm.toUpperCase(),
      createdAt,
    };
  }

  /** 当前密钥的二维码 PNG（已生成即可获取） */
  async qrCodePng(): Promise<{ buffer: Buffer; otpauthUrl: string; secret: string }> {
    const state = await this.store.read();
    if (!state.secret) {
      throw AppError.conflict(ErrorCodes.TOTP_NOT_CONFIGURED, '尚未生成 TOTP 密钥，请先调用 POST /api/totp/setup');
    }
    const otpauthUrl = this.otpauthUrl(state.secret, this.bindingOf(state));
    const buffer = await QRCode.toBuffer(otpauthUrl, { type: 'png', errorCorrectionLevel: 'M', margin: 1, width: 320 });
    return { buffer, otpauthUrl, secret: state.secret };
  }

  /** 用验证码激活（绑定完成） */
  async activate(code: string): Promise<{ enabledAt: string }> {
    const updated = await this.store.update((current) => {
      if (!current.secret) {
        throw AppError.conflict(ErrorCodes.TOTP_NOT_CONFIGURED, '尚未生成 TOTP 密钥，请先调用 POST /api/totp/setup');
      }
      if (current.enabled) {
        throw AppError.conflict(ErrorCodes.TOTP_ALREADY_ENABLED, 'TOTP 已激活，无需重复验证');
      }
      const binding = this.bindingOf(current);
      const result = verifyTotp(current.secret, code, {
        digits: binding.digits,
        period: binding.period,
        algorithm: binding.algorithm,
        window: this.settings.window,
      });
      if (!result.valid) {
        throw AppError.forbidden(ErrorCodes.TOTP_INVALID, '验证码错误，请确认手机时间准确后重试');
      }
      return {
        ...current,
        enabled: true,
        enabledAt: new Date().toISOString(),
        lastUsedStep: this.settings.preventReplay ? result.step : current.lastUsedStep,
      };
    });
    return { enabledAt: updated.enabledAt ?? new Date().toISOString() };
  }

  /** 高危操作校验：必须已激活 + 验证码正确 + 未重放 */
  async consume(code: string): Promise<void> {
    await this.store.update((current) => {
      if (!current.secret) {
        throw AppError.forbidden(ErrorCodes.TOTP_NOT_ENABLED, '尚未绑定 TOTP，禁止执行高危操作');
      }
      if (!current.enabled) {
        throw AppError.forbidden(
          ErrorCodes.TOTP_NOT_ENABLED,
          'TOTP 尚未激活，请先扫码并通过 POST /api/totp/verify 完成绑定',
        );
      }
      const binding = this.bindingOf(current);
      const result = verifyTotp(current.secret, code, {
        digits: binding.digits,
        period: binding.period,
        algorithm: binding.algorithm,
        window: this.settings.window,
        minStepExclusive: this.settings.preventReplay ? current.lastUsedStep : null,
      });
      if (!result.valid) {
        throw AppError.forbidden(
          ErrorCodes.TOTP_INVALID,
          this.settings.preventReplay ? '二次验证码无效或已被使用（同一验证码只能使用一次）' : '二次验证码无效',
        );
      }
      return {
        ...current,
        lastUsedStep: this.settings.preventReplay ? result.step : current.lastUsedStep,
        usedCount: current.usedCount + 1,
      };
    });
  }

  /** 供命令行使用：清除密钥 */
  async reset(): Promise<{ hadSecret: boolean; wasEnabled: boolean }> {
    const state = await this.store.read();
    const hadSecret = state.secret !== null;
    const wasEnabled = state.enabled;
    await this.store.reset();
    return { hadSecret, wasEnabled };
  }
}
