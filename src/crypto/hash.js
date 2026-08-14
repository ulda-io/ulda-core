import { base64ToBytes, hexToBytes } from "../bytes/index.js";
import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export const WEB_CRYPTO_ALGORITHMS = Object.freeze([
  "SHA-1",
  "SHA-256",
  "SHA-384",
  "SHA-512"
]);

export function createHashProvider(options = {}) {
  const {
    externalHashers = {},
    loadScriptOnce,
    cryptoImpl = globalThis.crypto
  } = options;

  const hash = async(u8, alg = "SHA-256") => {
    if (WEB_CRYPTO_ALGORITHMS.includes(alg))
      return new Uint8Array(await cryptoImpl.subtle.digest(alg, u8));
    const ext = externalHashers[alg];
    if (!ext)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_HASHER_NOT_REGISTERED,
        `Hasher <${alg}> not registered`, {
          operation: "hash",
          details: { hash: alg }
        }
      );
    if (ext.cdn && !ext.ready) {
      await loadScriptOnce(ext.cdn);
      ext.ready = true;
    }
    const raw = await ext.fn(u8),
      fmt = ext.output ?? "bytes",
      bytes =
      fmt === "bytes" ?
      raw :
      fmt === "hex" ?
      hexToBytes(raw) :
      fmt === "base64" ?
      base64ToBytes(raw) :
      (() => {
        throw new UldaError(
          ULDA_ERROR_CODES.ULDA_HASHER_OUTPUT_UNSUPPORTED,
          `Unsupported output ${fmt}`, {
            operation: "hash",
            details: { hash: alg, output: fmt }
          }
        );
      })();
    if (ext.size && bytes.length * 8 !== ext.size)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_HASHER_SIZE_MISMATCH,
        `Hasher <${alg}> size mismatch`, {
          operation: "hash",
          details: {
            hash: alg,
            expectedSize: ext.size,
            actualSize: bytes.length * 8
          }
        }
      );
    return bytes;
  };

  const hashIter = async(u8, t, alg = "SHA-256") => {
    let h = u8;
    for (let i = 0; i < t; i++) h = await hash(h, alg);
    return h;
  };

  return { hash, hashIter };
}
