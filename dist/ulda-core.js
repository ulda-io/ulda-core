// src/bytes/index.js
function bytesToHex(u8) {
  return [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(str) {
  return Uint8Array.from(str.match(/../g).map((h) => parseInt(h, 16)));
}
function bytesToBase64(u8) {
  return btoa(String.fromCharCode(...u8));
}
function base64ToBytes(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
function guessToBytes(str) {
  return /^[0-9a-f]+$/i.test(str) && str.length % 2 === 0 ? hexToBytes(str) : base64ToBytes(str);
}
function indexToBytes(idx) {
  let b = typeof idx === "bigint" ? idx : BigInt(idx);
  if (b === 0n) return Uint8Array.of(0);
  const r = [];
  while (b > 0n) {
    r.unshift(Number(b & 0xffn));
    b >>= 8n;
  }
  return Uint8Array.from(r);
}
function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let off = 0;
  arrs.forEach((a) => (out.set(a, off), off += a.length));
  return out;
}
function equalBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
function exportBytes(bytes, format) {
  return ({ base64: bytesToBase64, bytes: (x) => x, hex: bytesToHex }[format] ?? bytesToHex)(bytes);
}
function importBytes(input, format) {
  return input instanceof Uint8Array ? input : ({ hex: hexToBytes, base64: base64ToBytes }[format] ?? guessToBytes)(input);
}

// src/errors/codes.js
var ULDA_ERROR_CODES = Object.freeze({
  ULDA_FORMAT_SENTINEL: "ULDA_FORMAT_SENTINEL",
  ULDA_FORMAT_HEADER: "ULDA_FORMAT_HEADER",
  ULDA_FORMAT_SIZE: "ULDA_FORMAT_SIZE",
  ULDA_FORMAT_BODY_DIVISION: "ULDA_FORMAT_BODY_DIVISION",
  ULDA_FORMAT_UNKNOWN_MODE: "ULDA_FORMAT_UNKNOWN_MODE",
  ULDA_FORMAT_UNKNOWN_ALGORITHM: "ULDA_FORMAT_UNKNOWN_ALGORITHM",
  ULDA_HASHER_NOT_REGISTERED: "ULDA_HASHER_NOT_REGISTERED",
  ULDA_HASHER_OUTPUT_UNSUPPORTED: "ULDA_HASHER_OUTPUT_UNSUPPORTED",
  ULDA_HASHER_SIZE_MISMATCH: "ULDA_HASHER_SIZE_MISMATCH",
  ULDA_MODE_UNSUPPORTED: "ULDA_MODE_UNSUPPORTED",
  ULDA_MODE_EMPTY_BLOCKS: "ULDA_MODE_EMPTY_BLOCKS",
  ULDA_VERIFY_INCOMPATIBLE_PARAMS: "ULDA_VERIFY_INCOMPATIBLE_PARAMS",
  ULDA_VERIFY_INVALID_GAP: "ULDA_VERIFY_INVALID_GAP",
  ULDA_CONFIG_INVALID: "ULDA_CONFIG_INVALID",
  ULDA_RANDOM_UNAVAILABLE: "ULDA_RANDOM_UNAVAILABLE",
  ULDA_INTERNAL_ERROR: "ULDA_INTERNAL_ERROR"
});

// src/errors/UldaError.js
var PRIVATE_DETAIL_KEYS = /* @__PURE__ */ new Set([
  "origin",
  "blocks",
  "sigBytes",
  "bytes",
  "raw",
  "secret",
  "privateKey",
  "preimage"
]);
function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
function sanitizeDetails(value) {
  if (Array.isArray(value)) return value.map((item) => sanitizeDetails(item));
  if (!isPlainObject(value)) return value;
  const sanitized = {};
  for (const [key, entry] of Object.entries(value)) {
    if (PRIVATE_DETAIL_KEYS.has(key)) continue;
    sanitized[key] = sanitizeDetails(entry);
  }
  return sanitized;
}
var UldaError = class extends Error {
  constructor(code, message, options = {}) {
    super(message, { cause: options.cause });
    this.name = "UldaError";
    this.code = code;
    this.operation = options.operation;
    this.details = options.details;
    this.cause = options.cause;
  }
  toLogObject() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      operation: this.operation,
      details: sanitizeDetails(this.details),
      causeName: this.cause?.name,
      causeMessage: this.cause?.message
    };
  }
};

// src/codecs/compactHeader.js
var COMPACT_HEADER_PREFIX_NIBBLE = 0;
var COMPACT_HEADER_SUFFIX_NIBBLE = 0;
var COMPACT_HEADER_FLAGS = Object.freeze({
  BACKUP_SIZE: 128,
  N: 64,
  ALGORITHM: 32,
  AGE: 16,
  BACKUP_DESCRIPTOR: 8,
  MODE_X: 4,
  FUTURE_MODE: 2,
  BACKUP_ACTIVE: 1
});
var COMPACT_HEADER_DEFAULTS = Object.freeze({
  N: 5,
  algorithm: 2,
  mode: "S",
  age: 0n
});
var BASE_HEADER_BYTES = 3;
var OPTIONAL_FIELDS_BIT_OFFSET = 20;
function compactHeaderError(code, message, details) {
  return new UldaError(code, message, {
    operation: "compactHeader",
    details
  });
}
function assertUint8(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      `invalid ${name}`,
      { [name]: value }
    );
  }
}
function assertUint8Array(value, name) {
  if (!(value instanceof Uint8Array)) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      `invalid ${name}`,
      { type: typeof value }
    );
  }
}
function readBits(bytes, bitOffset, bitLength) {
  let value = 0;
  for (let i = 0; i < bitLength; i++) {
    const bitIndex = bitOffset + i;
    const byte = bytes[bitIndex >>> 3];
    const bit = byte >>> 7 - (bitIndex & 7) & 1;
    value = value << 1 | bit;
  }
  return value;
}
function writeBits(bytes, bitOffset, bitLength, value) {
  for (let i = 0; i < bitLength; i++) {
    const shift = bitLength - 1 - i;
    const bit = value >>> shift & 1;
    const bitIndex = bitOffset + i;
    const byteIndex = bitIndex >>> 3;
    const mask = 1 << 7 - (bitIndex & 7);
    if (bit) bytes[byteIndex] |= mask;
    else bytes[byteIndex] &= ~mask;
  }
}
function readByteAtBitOffset(bytes, bitOffset) {
  return readBits(bytes, bitOffset, 8);
}
function writeByteAtBitOffset(bytes, bitOffset, value) {
  writeBits(bytes, bitOffset, 8, value);
}
function bigIntToFixedBytes(value, byteLength) {
  if (typeof value !== "bigint" || value < 0n) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid age",
      { age: value }
    );
  }
  const max = 1n << BigInt(byteLength * 8);
  if (value >= max) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "age does not fit",
      { ageBytes: byteLength }
    );
  }
  const bytes = new Uint8Array(byteLength);
  let remaining = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}
function fixedBytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = value << 8n | BigInt(byte);
  return value;
}
function encodeCompactHeader(options = {}) {
  const forceFields = options.forceFields ?? {};
  let inclusive = 0;
  const optionalBytes = [];
  const N = options.N ?? COMPACT_HEADER_DEFAULTS.N;
  const algorithm = options.algorithm ?? COMPACT_HEADER_DEFAULTS.algorithm;
  const mode = options.mode ?? COMPACT_HEADER_DEFAULTS.mode;
  const age = options.age ?? COMPACT_HEADER_DEFAULTS.age;
  const ageBytes = options.ageBytes ?? 4;
  const backupActive = options.backupActive === true;
  const hasDescriptor = options.backupDescriptor !== void 0 && options.backupDescriptor.length > 0;
  const hasBackupSize = options.backupSize !== void 0 || forceFields.backupSize === true || hasDescriptor;
  if (mode !== "S" && mode !== "X") {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid mode",
      { mode }
    );
  }
  if (mode === "X") inclusive |= COMPACT_HEADER_FLAGS.MODE_X;
  if (backupActive) inclusive |= COMPACT_HEADER_FLAGS.BACKUP_ACTIVE;
  if (options.N !== void 0 || forceFields.N === true) assertUint8(N, "N");
  if (options.algorithm !== void 0 || forceFields.algorithm === true) {
    assertUint8(algorithm, "algorithm");
  }
  if (options.age !== void 0 || forceFields.age === true) {
    if (ageBytes !== 4 && ageBytes !== 8) {
      throw compactHeaderError(
        ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
        "invalid ageBytes",
        { ageBytes }
      );
    }
  }
  if (options.backupDescriptor !== void 0) {
    assertUint8Array(options.backupDescriptor, "backupDescriptor");
  }
  const backupSize = options.backupSize ?? (options.backupDescriptor?.length ?? 0);
  if (hasBackupSize) assertUint8(backupSize, "backupSize");
  if (hasDescriptor && backupSize !== options.backupDescriptor.length) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "backupSize does not match backupDescriptor length",
      {
        backupSize,
        descriptorLength: options.backupDescriptor.length
      }
    );
  }
  if (hasBackupSize) {
    inclusive |= COMPACT_HEADER_FLAGS.BACKUP_SIZE;
    optionalBytes.push(backupSize);
  }
  if (options.N !== void 0 && N !== COMPACT_HEADER_DEFAULTS.N || forceFields.N === true) {
    inclusive |= COMPACT_HEADER_FLAGS.N;
    optionalBytes.push(N);
  }
  if (options.algorithm !== void 0 && algorithm !== COMPACT_HEADER_DEFAULTS.algorithm || forceFields.algorithm === true) {
    inclusive |= COMPACT_HEADER_FLAGS.ALGORITHM;
    optionalBytes.push(algorithm);
  }
  if (options.age !== void 0 && age !== COMPACT_HEADER_DEFAULTS.age || forceFields.age === true) {
    inclusive |= COMPACT_HEADER_FLAGS.AGE;
    optionalBytes.push(...bigIntToFixedBytes(age, ageBytes));
  }
  if (hasDescriptor) {
    inclusive |= COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR;
    optionalBytes.push(...options.backupDescriptor);
  }
  const headerSize = BASE_HEADER_BYTES + optionalBytes.length;
  if (headerSize > 255) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_SIZE,
      "compact header too large",
      { headerSize }
    );
  }
  const header = new Uint8Array(headerSize);
  writeBits(header, 0, 4, COMPACT_HEADER_PREFIX_NIBBLE);
  writeBits(header, 4, 8, headerSize);
  writeBits(header, 12, 8, inclusive);
  let bitOffset = OPTIONAL_FIELDS_BIT_OFFSET;
  for (const byte of optionalBytes) {
    writeByteAtBitOffset(header, bitOffset, byte);
    bitOffset += 8;
  }
  writeBits(header, bitOffset, 4, COMPACT_HEADER_SUFFIX_NIBBLE);
  return header;
}
function decodeCompactHeader(input) {
  assertUint8Array(input, "input");
  if (input.length < BASE_HEADER_BYTES) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_SIZE,
      "compact header is too short",
      { inputLength: input.length }
    );
  }
  const prefix = readBits(input, 0, 4);
  if (prefix !== COMPACT_HEADER_PREFIX_NIBBLE) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL,
      "invalid compact header prefix",
      { prefix }
    );
  }
  const headerSize = readBits(input, 4, 8);
  if (headerSize < BASE_HEADER_BYTES) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "invalid compact header size",
      { headerSize }
    );
  }
  if (headerSize > input.length) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_SIZE,
      "compact header exceeds input length",
      { headerSize, inputLength: input.length }
    );
  }
  const inclusive = readBits(input, 12, 8);
  const flags = {
    hasBackupSize: Boolean(inclusive & COMPACT_HEADER_FLAGS.BACKUP_SIZE),
    hasN: Boolean(inclusive & COMPACT_HEADER_FLAGS.N),
    hasAlgorithm: Boolean(inclusive & COMPACT_HEADER_FLAGS.ALGORITHM),
    hasAge: Boolean(inclusive & COMPACT_HEADER_FLAGS.AGE),
    hasBackupDescriptor: Boolean(inclusive & COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR),
    modeX: Boolean(inclusive & COMPACT_HEADER_FLAGS.MODE_X),
    futureMode: Boolean(inclusive & COMPACT_HEADER_FLAGS.FUTURE_MODE),
    backupActive: Boolean(inclusive & COMPACT_HEADER_FLAGS.BACKUP_ACTIVE)
  };
  if (flags.hasBackupDescriptor && !flags.hasBackupSize) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "backup descriptor requires backupSize",
      { inclusive }
    );
  }
  let knownOptionalBytes = 0;
  if (flags.hasBackupSize) knownOptionalBytes += 1;
  if (flags.hasN) knownOptionalBytes += 1;
  if (flags.hasAlgorithm) knownOptionalBytes += 1;
  let bitOffset = OPTIONAL_FIELDS_BIT_OFFSET;
  let backupSize = 0;
  if (flags.hasBackupSize) {
    backupSize = readByteAtBitOffset(input, bitOffset);
    bitOffset += 8;
  }
  if (flags.hasBackupDescriptor) knownOptionalBytes += backupSize;
  const optionalByteCount = headerSize - BASE_HEADER_BYTES;
  const ageBytes = flags.hasAge ? optionalByteCount - knownOptionalBytes : 0;
  if (flags.hasAge && ageBytes !== 4 && ageBytes !== 8) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "unsupported compact header age length",
      { ageBytes }
    );
  }
  if (!flags.hasAge && optionalByteCount !== knownOptionalBytes) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "invalid compact header optional field layout",
      { optionalByteCount, knownOptionalBytes }
    );
  }
  if (flags.hasAge && optionalByteCount !== knownOptionalBytes + ageBytes) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_HEADER,
      "invalid compact header optional field layout",
      { optionalByteCount, knownOptionalBytes, ageBytes }
    );
  }
  const N = flags.hasN ? readByteAtBitOffset(input, bitOffset) : COMPACT_HEADER_DEFAULTS.N;
  if (flags.hasN) bitOffset += 8;
  const algorithm = flags.hasAlgorithm ? readByteAtBitOffset(input, bitOffset) : COMPACT_HEADER_DEFAULTS.algorithm;
  if (flags.hasAlgorithm) bitOffset += 8;
  let age = COMPACT_HEADER_DEFAULTS.age;
  if (flags.hasAge) {
    const ageBuffer = new Uint8Array(ageBytes);
    for (let i = 0; i < ageBytes; i++) {
      ageBuffer[i] = readByteAtBitOffset(input, bitOffset);
      bitOffset += 8;
    }
    age = fixedBytesToBigInt(ageBuffer);
  }
  let backupDescriptor = new Uint8Array(0);
  if (flags.hasBackupDescriptor) {
    backupDescriptor = new Uint8Array(backupSize);
    for (let i = 0; i < backupSize; i++) {
      backupDescriptor[i] = readByteAtBitOffset(input, bitOffset);
      bitOffset += 8;
    }
  }
  const suffix = readBits(input, bitOffset, 4);
  if (suffix !== COMPACT_HEADER_SUFFIX_NIBBLE) {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL,
      "invalid compact header suffix",
      { suffix }
    );
  }
  return {
    headerSize,
    inclusive,
    flags,
    N,
    algorithm,
    mode: flags.modeX ? "X" : "S",
    age,
    ageBytes,
    backupSize,
    backupDescriptor,
    bodyOffset: headerSize
  };
}
function splitCompactHeaderAndBody(input) {
  const header = decodeCompactHeader(input);
  return {
    header,
    body: input.slice(header.headerSize)
  };
}

// src/codecs/v1.js
var DEFAULT_V1_ENCODER = {
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
    CUSTOM: 255
  }
};
var DEFAULT_V1_DECODER = {
  mode: { 1: "S", 2: "X" },
  algorithm: Object.fromEntries(
    Object.entries(DEFAULT_V1_ENCODER.algorithm).map(([name, code]) => [code, name])
  )
};
function createV1Codec(options = {}) {
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
  const decodeOrigin = (pkg) => {
    const bytes = importBytes(pkg, getExportFormat()), hdr = bytes[1];
    if (bytes[0] || bytes[hdr - 1])
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL,
        "sentinel",
        {
          operation: "decodeOrigin",
          details: {
            headerLength: hdr,
            actualSize: bytes.length
          }
        }
      );
    const N = bytes[2], mode = decoder.mode[bytes[3]] ?? "U", alg = decoder.algorithm[bytes[4]] ?? "UNK";
    let idx = 0n;
    for (let i = 5; i < hdr - 1; i++) idx = idx << 8n | BigInt(bytes[i]);
    const body = bytes.slice(hdr), blkLen = body.length / N;
    if (!Number.isInteger(blkLen))
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_FORMAT_BODY_DIVISION,
        "div",
        {
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
  const decodeWitness = (pkg) => {
    const bytes = importBytes(pkg, getExportFormat()), hdr = bytes[1], N = bytes[2], mode = decoder.mode[bytes[3]] ?? "U", alg = decoder.algorithm[bytes[4]] ?? "UNK";
    let idx = 0n;
    for (let i = 5; i < hdr - 1; i++) idx = idx << 8n | BigInt(bytes[i]);
    const sigBytes = bytes.slice(hdr), originLen = (getOriginSize() ?? 256) >>> 3, rest = sigBytes.length - originLen, blkLen = rest / (N - 1);
    if (rest < 0 || !Number.isInteger(blkLen))
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
    const blocks = [sigBytes.slice(0, originLen)];
    for (let i = 0; i < N - 1; i++)
      blocks.push(sigBytes.slice(originLen + i * blkLen, originLen + (i + 1) * blkLen));
    return { bytes, N, mode, alg, index: idx, sigBytes, originLen, blkLen, blocks };
  };
  const encodeOrigin = (originObj, index = 0n, meta = {}) => {
    const N = meta.N ?? originObj.origin?.length ?? 5, mode = meta.mode ?? "S", hash = meta.hash ?? meta.alg ?? "SHA-256", hdr = makeHeader(N, mode, hash, indexToBytes(index));
    return exportBytes(concatBytes(hdr, ...originObj.origin), getExportFormat());
  };
  const encodeWitness = (sigBytes, meta) => {
    const hash = meta.hash ?? meta.alg, hdr = makeHeader(meta.N, meta.mode, hash, indexToBytes(meta.index));
    return exportBytes(concatBytes(hdr, sigBytes), getExportFormat());
  };
  const packWitness = (sigBytes, meta) => encodeWitness(sigBytes, meta);
  const splitWitnessBlocks = (p) => p.blocks ?? (() => {
    const { originLen, blkLen, sigBytes, N } = p, a = [sigBytes.slice(0, originLen)];
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

// src/codecs/compactV1.js
var DEFAULT_COMPACT_V1_OPTIONS = Object.freeze({
  exportFormat: "hex",
  originSize: 256,
  N: 5,
  mode: "S",
  algorithm: "SHA-256"
});
var COMPACT_V1_AGE_BYTES = 4;
var COMPACT_V1_MAX_AGE = 0xffffffffn;
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
  if (!Number.isInteger(code) || code < 0 || code > 255) {
    throw compactV1Error(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid algorithm",
      { algorithm }
    );
  }
  return code;
}
function assertCompactV1AgeOptions(meta) {
  if (meta.ageBytes !== void 0 && meta.ageBytes !== COMPACT_V1_AGE_BYTES) {
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
function createCompactV1Codec(options = {}) {
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
  const decodeHeader = (pkg) => {
    const bytes = importBytes(pkg, getExportFormat());
    const header = splitCompactHeaderAndBody(bytes).header;
    assertCanonicalDecodedHeader(header);
    return header;
  };
  const decodeBytes = (pkg) => {
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
  const decodeOrigin = (pkg) => {
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
  const splitWitnessBlocks = (p) => p.blocks ?? (() => {
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
  const decodeWitness = (pkg) => {
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

// src/codecs/registry.js
var ULDA_CODEC_PACKS = Object.freeze({
  SIMPLE_SIG: "simpleSig",
  V1: "v1",
  COMPACT_V1: "compactV1"
});
function normalizeCodecPack(pack) {
  if (pack === void 0 || pack === null) return ULDA_CODEC_PACKS.COMPACT_V1;
  if (pack === ULDA_CODEC_PACKS.SIMPLE_SIG) return ULDA_CODEC_PACKS.SIMPLE_SIG;
  if (pack === ULDA_CODEC_PACKS.V1) return ULDA_CODEC_PACKS.SIMPLE_SIG;
  if (pack === ULDA_CODEC_PACKS.COMPACT_V1 || pack === "compact") {
    return ULDA_CODEC_PACKS.COMPACT_V1;
  }
  throw new UldaError(
    ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
    "unknown codec pack",
    {
      operation: "normalizeCodecPack",
      details: { pack }
    }
  );
}
function createCodecForPack(options = {}) {
  const {
    pack,
    encoder,
    decoder,
    getExportFormat,
    getOriginSize
  } = options;
  const id = normalizeCodecPack(pack);
  if (id === ULDA_CODEC_PACKS.COMPACT_V1) {
    return {
      id,
      codec: createCompactV1Codec({
        encoder,
        decoder,
        getExportFormat,
        getOriginSize
      })
    };
  }
  return {
    id: ULDA_CODEC_PACKS.SIMPLE_SIG,
    codec: createV1Codec({
      encoder,
      decoder,
      getExportFormat,
      getOriginSize
    })
  };
}

// src/config/defaults.js
var DEFAULT_ULDA_VERSION = "1";
var DEFAULT_EXPORT_FORMAT = "hex";
var DEFAULT_SIGN_CONFIG = Object.freeze({
  N: 5,
  mode: "S",
  hash: "SHA-256",
  originSize: 256,
  pack: "compactV1",
  ageBytes: 4
});

// src/config/algorithms.js
var DEFAULT_ENCODER = Object.freeze({
  mode: Object.freeze({ S: 1, X: 2 }),
  algorithm: Object.freeze({
    "SHA-1": 1,
    "SHA-256": 2,
    "SHA-384": 3,
    "SHA-512": 4,
    "SHA3-256": 5,
    "SHA3-512": 6,
    BLAKE3: 7,
    WHIRLPOOL: 8,
    CUSTOM: 255
  })
});
function createDefaultEncoder() {
  return {
    mode: { ...DEFAULT_ENCODER.mode },
    algorithm: { ...DEFAULT_ENCODER.algorithm }
  };
}
function createDecoderFromEncoder(encoder) {
  return {
    mode: Object.fromEntries(
      Object.entries(encoder.mode).map(([name, code]) => [code, name])
    ),
    algorithm: Object.fromEntries(
      Object.entries(encoder.algorithm).map(([name, code]) => [code, name])
    )
  };
}

// src/config/normalize.js
function normalizeConfig(cfg = {}) {
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

// src/config/customHashers.js
function registerCustomHasher(options) {
  const { cfg, config, encoder, decoder } = options;
  const s = cfg.sign ?? {};
  if (typeof s.func !== "function") return void 0;
  const id = s.hash ?? "CUSTOM";
  if (!s.hash) config.sign.hash = id;
  config.externalHashers[id] = {
    fn: s.func,
    output: s.output ?? "bytes",
    size: s.originSize ?? null,
    cdn: s.cdn ?? null,
    ready: true
  };
  if (!(id in encoder.algorithm)) encoder.algorithm[id] = 255;
  if (encoder.algorithm[id] === 255) decoder.algorithm[255] = id;
  return { id };
}

// src/crypto/hash.js
var WEB_CRYPTO_ALGORITHMS = Object.freeze([
  "SHA-1",
  "SHA-256",
  "SHA-384",
  "SHA-512"
]);
function createHashProvider(options = {}) {
  const {
    externalHashers = {},
    loadScriptOnce,
    cryptoImpl = globalThis.crypto
  } = options;
  const hash = async (u8, alg = "SHA-256") => {
    if (WEB_CRYPTO_ALGORITHMS.includes(alg))
      return new Uint8Array(await cryptoImpl.subtle.digest(alg, u8));
    const ext = externalHashers[alg];
    if (!ext)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_HASHER_NOT_REGISTERED,
        `Hasher <${alg}> not registered`,
        {
          operation: "hash",
          details: { hash: alg }
        }
      );
    if (ext.cdn && !ext.ready) {
      await loadScriptOnce(ext.cdn);
      ext.ready = true;
    }
    const raw = await ext.fn(u8), fmt = ext.output ?? "bytes", bytes = fmt === "bytes" ? raw : fmt === "hex" ? hexToBytes(raw) : fmt === "base64" ? base64ToBytes(raw) : (() => {
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_HASHER_OUTPUT_UNSUPPORTED,
        `Unsupported output ${fmt}`,
        {
          operation: "hash",
          details: { hash: alg, output: fmt }
        }
      );
    })();
    if (ext.size && bytes.length * 8 !== ext.size)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_HASHER_SIZE_MISMATCH,
        `Hasher <${alg}> size mismatch`,
        {
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
  const hashIter = async (u8, t, alg = "SHA-256") => {
    let h = u8;
    for (let i = 0; i < t; i++) h = await hash(h, alg);
    return h;
  };
  return { hash, hashIter };
}

// src/crypto/random.js
function createRandomProvider(options = {}) {
  const { cryptoImpl = globalThis.crypto } = options;
  const randomBytes = (len) => {
    if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== "function")
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_RANDOM_UNAVAILABLE,
        "Random source unavailable",
        {
          operation: "randomBytes",
          details: { requestedLength: len }
        }
      );
    return cryptoImpl.getRandomValues(new Uint8Array(len));
  };
  return { randomBytes };
}

// src/modes/modeS.js
var modeS = {
  id: "S",
  ladder: async (blocks, ctx) => {
    const sig = [];
    for (let i = 0; i < blocks.length; i++)
      sig.push(await ctx.hashIter(blocks[i], i, ctx.alg));
    return { sigBlocks: sig, final: sig.at(-1) };
  },
  verify: async (previousWitness, candidateWitness, ctx) => {
    const gap = candidateWitness.index - previousWitness.index;
    if (gap <= 0n || gap >= BigInt(previousWitness.N)) return false;
    const iterations = Number(gap);
    if (previousWitness.originLen !== candidateWitness.originLen || previousWitness.blkLen !== candidateWitness.blkLen)
      return false;
    const previousBlocks = ctx.splitWitnessBlocks(previousWitness), candidateBlocks = ctx.splitWitnessBlocks(candidateWitness);
    for (let i = 0; i < previousWitness.N - iterations; i++)
      if (!ctx.equalBytes(
        await ctx.hashIter(candidateBlocks[i], iterations, previousWitness.alg),
        previousBlocks[i + iterations]
      ))
        return false;
    return true;
  }
};

// src/modes/modeX.js
var modeX = {
  id: "X",
  ladder: async (blocks, ctx) => {
    if (!blocks?.length)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_MODE_EMPTY_BLOCKS,
        "_ladderX: empty blocks",
        {
          operation: "ladderX",
          details: { mode: "X" }
        }
      );
    const sig = [blocks[0]];
    let prev = blocks;
    for (let d = 1; d < blocks.length; d++) {
      const cur = [];
      for (let i = 0; i < prev.length - 1; i++)
        cur.push(await ctx.hash(ctx.concatBytes(prev[i], prev[i + 1]), ctx.alg));
      sig.push(cur[0]);
      prev = cur;
    }
    return { sigBlocks: sig, final: sig.at(-1) };
  },
  verify: async (previousWitness, candidateWitness, ctx) => {
    if (candidateWitness.index - previousWitness.index !== 1n) return false;
    const { N } = previousWitness;
    if (previousWitness.sigBytes.length !== candidateWitness.sigBytes.length || previousWitness.sigBytes.length % N)
      return false;
    const previousBlocks = ctx.splitWitnessBlocks(previousWitness), candidateBlocks = ctx.splitWitnessBlocks(candidateWitness);
    for (let d = 1; d < N; d++)
      if (!ctx.equalBytes(
        await ctx.hash(
          ctx.concatBytes(previousBlocks[d - 1], candidateBlocks[d - 1]),
          previousWitness.alg
        ),
        previousBlocks[d]
      ))
        return false;
    return true;
  }
};

// src/modes/index.js
var DEFAULT_MODES = Object.freeze({ S: modeS, X: modeX });

// src/core/New.js
function createOriginState(options) {
  const { N, originSize, randomBytes } = options;
  const len = originSize >>> 3;
  return {
    origin: Array.from({ length: N }, () => randomBytes(len))
  };
}

// src/core/sign.js
async function signOriginState(parsedOrigin, options) {
  const { modes, hash, hashIter, concatBytes: concatBytes2 } = options;
  const mode = parsedOrigin.mode === "X" ? modes.X : modes.S;
  const { sigBlocks } = await mode.ladder(parsedOrigin.origin, {
    hash,
    hashIter,
    concatBytes: concatBytes2,
    alg: parsedOrigin.alg
  });
  const sigBytes = concatBytes2(...sigBlocks);
  return {
    sigBytes,
    sigBlocks,
    index: parsedOrigin.index,
    N: parsedOrigin.N,
    mode: parsedOrigin.mode,
    alg: parsedOrigin.alg
  };
}

// src/core/stepUp.js
function stepUpOriginState(parsedOrigin, options) {
  const { randomBytes } = options;
  const next = parsedOrigin.origin.slice(1);
  next.push(randomBytes(parsedOrigin.blockLen));
  return { origin: next, index: parsedOrigin.index + 1n };
}

// src/core/verify.js
async function verifyWitnesses(previousWitness, candidateWitness, options) {
  const { modes, hash, hashIter, concatBytes: concatBytes2, equalBytes: equalBytes2, splitWitnessBlocks } = options;
  if (previousWitness.N !== candidateWitness.N || previousWitness.mode !== candidateWitness.mode || previousWitness.alg !== candidateWitness.alg)
    return false;
  if (candidateWitness.index <= previousWitness.index) return false;
  const ctx = { hash, hashIter, concatBytes: concatBytes2, equalBytes: equalBytes2, splitWitnessBlocks };
  return previousWitness.mode === "S" ? modes.S.verify(previousWitness, candidateWitness, ctx) : previousWitness.mode === "X" ? modes.X.verify(previousWitness, candidateWitness, ctx) : false;
}

// src/runtime/operations.js
function createUldaOperations(options) {
  const {
    config,
    codec,
    modes,
    hash,
    hashIter,
    randomBytes,
    concatBytes: concatBytes2,
    equalBytes: equalBytes2
  } = options;
  const randomBlock = (len) => randomBytes(len);
  const originGenerator = () => createOriginState({
    N: config.sign.N,
    originSize: config.sign.originSize,
    randomBytes: randomBlock
  });
  const newOriginPackage = (index = 0n) => codec.encodeOrigin(originGenerator(), index, {
    N: config.sign.N,
    mode: config.sign.mode,
    hash: config.sign.hash,
    ageBytes: config.sign.ageBytes
  });
  const stepUpPackage = (pkg) => {
    const parsedOrigin = codec.decodeOrigin(pkg), next = stepUpOriginState(parsedOrigin, { randomBytes: randomBlock });
    return codec.encodeOrigin({ origin: next.origin }, next.index, {
      N: config.sign.N,
      mode: config.sign.mode,
      hash: config.sign.hash,
      ageBytes: config.sign.ageBytes
    });
  };
  const signPackage = async (pkg) => {
    const parsedOrigin = codec.decodeOrigin(pkg), result = await signOriginState(parsedOrigin, {
      modes,
      hash,
      hashIter,
      concatBytes: concatBytes2
    });
    return codec.packWitness(result.sigBytes, {
      index: result.index,
      N: result.N,
      mode: result.mode,
      alg: result.alg,
      ageBytes: config.sign.ageBytes
    });
  };
  const verifyPackages = async (previousPackage, candidatePackage) => {
    const previousWitness = codec.decodeWitness(previousPackage), candidateWitness = codec.decodeWitness(candidatePackage);
    return verifyWitnesses(previousWitness, candidateWitness, {
      modes,
      hash,
      hashIter,
      concatBytes: concatBytes2,
      equalBytes: equalBytes2,
      splitWitnessBlocks: codec.splitWitnessBlocks
    });
  };
  return {
    randomBlock,
    originGenerator,
    newOriginPackage,
    stepUpPackage,
    signPackage,
    verifyPackages
  };
}

// ulda-sign.js
var UldaSign = class _UldaSign {
  constructor(cfg = {}) {
    const g = this.globalConfig = normalizeConfig(cfg);
    this.externalHashers = g.externalHashers;
    this.encoder = createDefaultEncoder();
    this.decoder = createDecoderFromEncoder(this.encoder);
    registerCustomHasher({ cfg, config: g, encoder: this.encoder, decoder: this.decoder });
    const codecSelection = createCodecForPack({
      pack: g.sign.pack,
      encoder: this.encoder,
      decoder: this.decoder,
      getExportFormat: () => g.fmt.export,
      getOriginSize: () => g.sign.originSize
    });
    this.codecPack = codecSelection.id;
    const codec = this.codec = codecSelection.codec;
    const cv = this.convert = {
      bytesToHex,
      hexToBytes,
      bytesToBase64,
      base64ToBytes,
      guessToBytes,
      indexToBytes,
      concatBytes,
      equalBytes,
      export: (bytes) => exportBytes(bytes, g.fmt.export),
      importToBytes: (d) => importBytes(d, g.fmt.export),
      splitSig: (p) => codec.splitWitnessBlocks(p)
    };
    const hashProvider = this.hashProvider = createHashProvider({
      externalHashers: g.externalHashers,
      loadScriptOnce: _UldaSign.loadScriptOnce,
      cryptoImpl: globalThis.crypto
    });
    const randomProvider = this.randomProvider = createRandomProvider({
      cryptoImpl: globalThis.crypto
    });
    const enc = this.enc = {
      hash: hashProvider.hash,
      hashIter: hashProvider.hashIter,
      ladder: async (blocks, mode = "S", alg = "SHA-256") => mode === "X" ? enc._ladderX(blocks, alg) : enc._ladderS(blocks, alg),
      _ladderS: async (blocks, alg) => modeS.ladder(blocks, { hashIter: enc.hashIter, alg }),
      _ladderX: async (blocks, alg = "SHA-256") => modeX.ladder(blocks, { hash: enc.hash, concatBytes: cv.concatBytes, alg })
    };
    const operations = this.operations = createUldaOperations({
      config: g,
      codec,
      modes: { S: modeS, X: modeX },
      hash: enc.hash,
      hashIter: enc.hashIter,
      randomBytes: (len) => randomProvider.randomBytes(len),
      concatBytes: cv.concatBytes,
      equalBytes: cv.equalBytes
    });
    this.actions = {
      Sign: (pkg) => operations.signPackage(pkg),
      VerifyS: async (previousWitness, candidateWitness) => modeS.verify(previousWitness, candidateWitness, {
        hashIter: enc.hashIter,
        equalBytes: cv.equalBytes,
        splitWitnessBlocks: cv.splitSig
      }),
      VerifyX: async (previousWitness, candidateWitness) => modeX.verify(previousWitness, candidateWitness, {
        hash: enc.hash,
        concatBytes: cv.concatBytes,
        equalBytes: cv.equalBytes,
        splitWitnessBlocks: cv.splitSig
      }),
      Verify: (previousWitness, candidateWitness) => operations.verifyPackages(previousWitness, candidateWitness),
      import: {
        signature: (pkg) => codec.decodeWitness(pkg),
        origin: (pkg) => codec.decodeOrigin(pkg)
      },
      OriginGenerator: () => operations.originGenerator(),
      RandomBlock: (len) => operations.randomBlock(len),
      _hdr: (N, mode, alg, idxBytes) => {
        if (typeof codec.makeHeader === "function") {
          return codec.makeHeader(N, mode, alg, idxBytes);
        }
        throw new UldaError(
          ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
          "Legacy v1 header is not available for compactV1",
          {
            operation: "actions._hdr",
            details: { pack: this.codecPack }
          }
        );
      },
      NewExporter: (originObj, index = 0n) => {
        const { N, mode, hash } = g.sign;
        return codec.encodeOrigin(originObj, index, {
          N,
          mode,
          hash,
          ageBytes: g.sign.ageBytes
        });
      },
      SignExporter: (sigBytes, index, N, mode, hash) => codec.encodeWitness(sigBytes, { index, N, mode, hash, ageBytes: g.sign.ageBytes }),
      PackSignature: (sigBytes, m) => codec.packWitness(sigBytes, m),
      StepUp: (pkg) => operations.stepUpPackage(pkg)
    };
  }
  static loadScriptOnce(src) {
    return new Promise((res, rej) => {
      if (document.querySelector(`script[src="${src}"]`)) return res();
      const s = document.createElement("script");
      s.src = src;
      s.onload = res;
      s.onerror = rej;
      document.head.appendChild(s);
    });
  }
  New(i = 0n) {
    return this.operations.newOriginPackage(i);
  }
  stepUp(pkg) {
    return this.operations.stepUpPackage(pkg);
  }
  sign(pkg) {
    return this.operations.signPackage(pkg);
  }
  verify(previousWitness, candidateWitness) {
    return this.operations.verifyPackages(previousWitness, candidateWitness);
  }
};
var ulda_sign_default = UldaSign;
export {
  ulda_sign_default as default
};
