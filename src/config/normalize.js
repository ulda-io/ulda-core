import {
  DEFAULT_EXPORT_FORMAT,
  DEFAULT_SIGN_CONFIG,
  DEFAULT_ULDA_VERSION
} from "./defaults.js";
import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export function normalizeConfig(cfg = {}) {
  const ageBytes = cfg?.sign?.ageBytes ?? DEFAULT_SIGN_CONFIG.ageBytes;
  if (ageBytes !== 4) {
    throw new UldaError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid ageBytes",
      {
        operation: "normalizeConfig",
        details: { ageBytes }
      }
    );
  }

  return {
    version: cfg.version ?? DEFAULT_ULDA_VERSION,
    fmt: { export: cfg?.fmt?.export ?? DEFAULT_EXPORT_FORMAT },
    sign: {
      N: cfg?.sign?.N ?? DEFAULT_SIGN_CONFIG.N,
      mode: cfg?.sign?.mode ?? DEFAULT_SIGN_CONFIG.mode,
      hash: cfg?.sign?.hash ?? DEFAULT_SIGN_CONFIG.hash,
      originSize: cfg?.sign?.originSize ?? DEFAULT_SIGN_CONFIG.originSize,
      pack: cfg?.sign?.pack ?? DEFAULT_SIGN_CONFIG.pack,
      ageBytes
    },
    externalHashers: cfg.externalHashers ?? {}
  };
}
