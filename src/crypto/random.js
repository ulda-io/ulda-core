import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export function createRandomProvider(options = {}) {
  const { cryptoImpl = globalThis.crypto } = options;

  const randomBytes = len => {
    if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== "function")
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_RANDOM_UNAVAILABLE,
        "Random source unavailable", {
          operation: "randomBytes",
          details: { requestedLength: len }
        }
      );
    return cryptoImpl.getRandomValues(new Uint8Array(len));
  };

  return { randomBytes };
}
