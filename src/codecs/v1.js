import { concatBytes, exportBytes, importBytes, indexToBytes } from "../bytes/index.js";
import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export const DEFAULT_V1_ENCODER = {
  mode: { S: 1, X: 2 },
  algorithm: {
    "SHA-1": 1,
    "SHA-256": 2,
    "SHA-384": 3,
    "SHA-512": 4,
    "SHA3-256": 5,
    "SHA3-512": 6,
    BLAKE3: 7,
    WHIRLPOOL: 8,
    CUSTOM: 0xff
  }
};

export const DEFAULT_V1_DECODER = {
  mode: { 1: "S", 2: "X" },
  algorithm: Object.fromEntries(
    Object.entries(DEFAULT_V1_ENCODER.algorithm).map(([name, code]) => [code, name])
  )
};

export function createV1Codec(options = {}) {
  const encoder = options.encoder ?? DEFAULT_V1_ENCODER;
  const decoder = options.decoder ?? DEFAULT_V1_DECODER;
  const getExportFormat = options.getExportFormat ?? (() => "hex");
  const getOriginSize = options.getOriginSize ?? (() => 256);

  const makeHeader = (N, mode, alg, idxBytes) => {
    const h = new Uint8Array(5 + idxBytes.length + 1);
    h.set([0, h.length, N, encoder.mode[mode] ?? 255, encoder.algorithm[alg] ?? 255]);
    h.set(idxBytes, 5);
    h[h.length - 1] = 0;
    return h;
  };

  const decodeOrigin = pkg => {
    const bytes = importBytes(pkg, getExportFormat()),
      hdr = bytes[1];
    if (bytes[0] || bytes[hdr - 1])
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL,
        "sentinel", {
          operation: "decodeOrigin",
          details: {
            headerLength: hdr,
            actualSize: bytes.length
          }
        }
      );
    const N = bytes[2],
      mode = decoder.mode[bytes[3]] ?? "U",
      alg = decoder.algorithm[bytes[4]] ?? "UNK";
    let idx = 0n;
    for (let i = 5; i < hdr - 1; i++) idx = (idx << 8n) | BigInt(bytes[i]);
    const body = bytes.slice(hdr),
      blkLen = body.length / N;
    if (!Number.isInteger(blkLen))
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_BODY_DIVISION,
        "div", {
          operation: "decodeOrigin",
          details: {
            N,
            bodyLength: body.length,
            blkLen
          }
        }
      );
    const origin = [];
    for (let i = 0; i < N; i++)
      origin.push(body.slice(i * blkLen, (i + 1) * blkLen));
    return { bytes, N, mode, alg, index: idx, blockLen: blkLen, origin };
  };

  const decodeWitness = pkg => {
    const bytes = importBytes(pkg, getExportFormat()),
      hdr = bytes[1],
      N = bytes[2],
      mode = decoder.mode[bytes[3]] ?? "U",
      alg = decoder.algorithm[bytes[4]] ?? "UNK";
    let idx = 0n;
    for (let i = 5; i < hdr - 1; i++) idx = (idx << 8n) | BigInt(bytes[i]);
    const sigBytes = bytes.slice(hdr),
      originLen = (getOriginSize() ?? 256) >>> 3,
      rest = sigBytes.length - originLen,
      blkLen = rest / (N - 1);
    if (rest < 0 || !Number.isInteger(blkLen))
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_SIZE,
        "SigImporter sizes", {
          operation: "decodeWitness",
          details: {
            N,
            originLen,
            sigLength: sigBytes.length,
            rest,
            blkLen
          }
        }
      );
    const blocks = [sigBytes.slice(0, originLen)];
    for (let i = 0; i < N - 1; i++)
      blocks.push(sigBytes.slice(originLen + i * blkLen, originLen + (i + 1) * blkLen));
    return { bytes, N, mode, alg, index: idx, sigBytes, originLen, blkLen, blocks };
  };

  const encodeOrigin = (originObj, index = 0n, meta = {}) => {
    const N = meta.N ?? originObj.origin?.length ?? 5,
      mode = meta.mode ?? "S",
      hash = meta.hash ?? meta.alg ?? "SHA-256",
      hdr = makeHeader(N, mode, hash, indexToBytes(index));
    return exportBytes(concatBytes(hdr, ...originObj.origin), getExportFormat());
  };

  const encodeWitness = (sigBytes, meta) => {
    const hash = meta.hash ?? meta.alg,
      hdr = makeHeader(meta.N, meta.mode, hash, indexToBytes(meta.index));
    return exportBytes(concatBytes(hdr, sigBytes), getExportFormat());
  };

  const packWitness = (sigBytes, meta) => encodeWitness(sigBytes, meta);

  const splitWitnessBlocks = p =>
    p.blocks ??
    (() => {
      const { originLen, blkLen, sigBytes, N } = p,
        a = [sigBytes.slice(0, originLen)];
      for (let i = 0; i < N - 1; i++)
        a.push(sigBytes.slice(originLen + i * blkLen, originLen + (i + 1) * blkLen));
      return a;
    })();

  return {
    makeHeader,
    decodeOrigin,
    decodeWitness,
    encodeOrigin,
    encodeWitness,
    packWitness,
    splitWitnessBlocks
  };
}
