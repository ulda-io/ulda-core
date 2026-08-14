import { concatBytes, exportBytes, importBytes } from "../bytes/index.js";
import {
  encodeCompactHeader,
  splitCompactHeaderAndBody
} from "./compactHeader.js";
import { DEFAULT_V1_DECODER, DEFAULT_V1_ENCODER } from "./v1.js";
import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

const DEFAULT_COMPACT_V1_OPTIONS = Object.freeze({
  exportFormat: "hex",
  originSize: 256,
  N: 5,
  mode: "S",
  algorithm: "SHA-256"
});
const COMPACT_V1_AGE_BYTES = 4;
const COMPACT_V1_MAX_AGE = 0xffffffffn;

function compactV1Error(code, message, details) {
  return new UldaError(code, message, {
    operation: "compactV1",
    details
  });
}

function resolveDefaults(defaults = {}) {
  return {
    ...DEFAULT_COMPACT_V1_OPTIONS,
    ...defaults
  };
}

function assertSupportedMode(mode) {
  if (mode !== "S" && mode !== "X") {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid mode",
      { mode }
    );
  }
}

function resolveAlgorithmCode(encoder, algorithm) {
  const code = encoder.algorithm[algorithm];
  if (!Number.isInteger(code) || code < 0 || code > 0xff) {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid algorithm",
      { algorithm }
    );
  }
  return code;
}

function assertCompactV1AgeOptions(meta) {
  if (meta.ageBytes !== undefined && meta.ageBytes !== COMPACT_V1_AGE_BYTES) {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "compactV1 ageBytes must be 4",
      { ageBytes: meta.ageBytes }
    );
  }
}

function assertCompactV1Age(age) {
  if (typeof age === "bigint" && age > COMPACT_V1_MAX_AGE) {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "compactV1 age does not fit uint32",
      { age }
    );
  }
}

function assertCanonicalDecodedHeader(header) {
  if (header.flags.hasAge && header.ageBytes !== COMPACT_V1_AGE_BYTES) {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "compactV1 age must be 4 bytes",
      { ageBytes: header.ageBytes }
    );
  }
}

export function createCompactV1Codec(options = {}) {
  const encoder = options.encoder ?? DEFAULT_V1_ENCODER;
  const decoder = options.decoder ?? DEFAULT_V1_DECODER;
  const defaults = resolveDefaults(options.defaults);
  const getExportFormat = options.getExportFormat ?? (() => defaults.exportFormat);
  const getOriginSize = options.getOriginSize ?? (() => defaults.originSize);
  const defaultAlgorithmCode = resolveAlgorithmCode(encoder, defaults.algorithm);

  const encodeHeader = (meta = {}) => {
    const N = meta.N ?? defaults.N;
    const mode = meta.mode ?? defaults.mode;
    const algorithm = meta.hash ?? meta.alg ?? meta.algorithm ?? defaults.algorithm;
    const algorithmCode = resolveAlgorithmCode(encoder, algorithm);
    const age = meta.index ?? meta.age ?? 0n;

    assertSupportedMode(mode);
    assertCompactV1AgeOptions(meta);
    assertCompactV1Age(age);

    return encodeCompactHeader({
      N,
      algorithm: algorithmCode,
      mode,
      age,
      ageBytes: COMPACT_V1_AGE_BYTES,
      backupActive: meta.backupActive,
      backupSize: meta.backupSize,
      backupDescriptor: meta.backupDescriptor,
      forceFields: {
        ...meta.forceFields,
        algorithm: meta.forceFields?.algorithm ?? algorithmCode !== defaultAlgorithmCode
      }
    });
  };

  const decodeHeader = pkg => {
    const bytes = importBytes(pkg, getExportFormat());
    const header = splitCompactHeaderAndBody(bytes).header;
    assertCanonicalDecodedHeader(header);
    return header;
  };

  const decodeBytes = pkg => {
    const bytes = importBytes(pkg, getExportFormat());
    const { header, body } = splitCompactHeaderAndBody(bytes);
    assertCanonicalDecodedHeader(header);
    return { bytes, header, body };
  };

  const encodeOrigin = (originObj, index = 0n, meta = {}) => {
    const header = encodeHeader({
      ...meta,
      index,
      N: meta.N ?? originObj.origin?.length ?? defaults.N
    });
    return exportBytes(concatBytes(header, ...originObj.origin), getExportFormat());
  };

  const decodeOrigin = pkg => {
    const { bytes, header, body } = decodeBytes(pkg);
    const N = header.N;
    const mode = header.mode;
    const alg = decoder.algorithm[header.algorithm] ?? "UNK";
    const index = header.age;
    const blockLen = body.length / N;

    if (!Number.isInteger(blockLen)) {
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_BODY_DIVISION,
        "div",
        {
          operation: "decodeOrigin",
          details: {
            N,
            bodyLength: body.length,
            blockLen
          }
        }
      );
    }

    const origin = [];
    for (let i = 0; i < N; i++) {
      origin.push(body.slice(i * blockLen, (i + 1) * blockLen));
    }
    return { bytes, N, mode, alg, index, blockLen, origin, header, body };
  };

  const splitWitnessBlocks = p =>
    p.blocks ??
    (() => {
      const { originLen, blkLen, sigBytes, N } = p;
      const blocks = [sigBytes.slice(0, originLen)];
      for (let i = 0; i < N - 1; i++) {
        blocks.push(sigBytes.slice(originLen + i * blkLen, originLen + (i + 1) * blkLen));
      }
      return blocks;
    })();

  const encodeWitness = (sigBytes, meta = {}) => {
    const header = encodeHeader(meta);
    return exportBytes(concatBytes(header, sigBytes), getExportFormat());
  };

  const decodeWitness = pkg => {
    const { bytes, header, body } = decodeBytes(pkg);
    const N = header.N;
    const mode = header.mode;
    const alg = decoder.algorithm[header.algorithm] ?? "UNK";
    const index = header.age;
    const sigBytes = body;
    const originLen = (getOriginSize() ?? DEFAULT_COMPACT_V1_OPTIONS.originSize) >>> 3;
    const rest = sigBytes.length - originLen;
    const blkLen = rest / (N - 1);

    if (rest < 0 || !Number.isInteger(blkLen)) {
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_SIZE,
        "SigImporter sizes",
        {
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
    }

    const blocks = splitWitnessBlocks({ originLen, blkLen, sigBytes, N });
    return { bytes, N, mode, alg, index, sigBytes, originLen, blkLen, blocks, header, body };
  };

  const packWitness = (sigBytes, meta) => encodeWitness(sigBytes, meta);

  return {
    encodeHeader,
    decodeHeader,
    encodeOrigin,
    decodeOrigin,
    encodeWitness,
    decodeWitness,
    packWitness,
    splitWitnessBlocks
  };
}
