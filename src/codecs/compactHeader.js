import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export const COMPACT_HEADER_PREFIX_NIBBLE = 0x0;
export const COMPACT_HEADER_SUFFIX_NIBBLE = 0x0;

export const COMPACT_HEADER_FLAGS = Object.freeze({
  BACKUP_SIZE: 0x80,
  N: 0x40,
  ALGORITHM: 0x20,
  AGE: 0x10,
  BACKUP_DESCRIPTOR: 0x08,
  MODE_X: 0x04,
  FUTURE_MODE: 0x02,
  BACKUP_ACTIVE: 0x01
});

export const COMPACT_HEADER_DEFAULTS = Object.freeze({
  N: 5,
  algorithm: 2,
  mode: "S",
  age: 0n
});

const BASE_HEADER_BYTES = 3;
const OPTIONAL_FIELDS_BIT_OFFSET = 20;

function compactHeaderError(code, message, details) {
  return new UldaError(code, message, {
    operation: "compactHeader",
    details
  });
}

function assertUint8(value, name) {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
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
    const bit = (byte >>> (7 - (bitIndex & 7))) & 1;
    value = (value << 1) | bit;
  }
  return value;
}

function writeBits(bytes, bitOffset, bitLength, value) {
  for (let i = 0; i < bitLength; i++) {
    const shift = bitLength - 1 - i;
    const bit = (value >>> shift) & 1;
    const bitIndex = bitOffset + i;
    const byteIndex = bitIndex >>> 3;
    const mask = 1 << (7 - (bitIndex & 7));
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
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function encodeCompactHeader(options = {}) {
  const forceFields = options.forceFields ?? {};
  let inclusive = 0;
  const optionalBytes = [];

  const N = options.N ?? COMPACT_HEADER_DEFAULTS.N;
  const algorithm = options.algorithm ?? COMPACT_HEADER_DEFAULTS.algorithm;
  const mode = options.mode ?? COMPACT_HEADER_DEFAULTS.mode;
  const age = options.age ?? COMPACT_HEADER_DEFAULTS.age;
  const ageBytes = options.ageBytes ?? 4;
  const backupActive = options.backupActive === true;
  const hasDescriptor = options.backupDescriptor !== undefined && options.backupDescriptor.length > 0;
  const hasBackupSize =
    options.backupSize !== undefined ||
    forceFields.backupSize === true ||
    hasDescriptor;

  if (mode !== "S" && mode !== "X") {
    throw compactHeaderError(
      ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
      "invalid mode",
      { mode }
    );
  }
  if (mode === "X") inclusive |= COMPACT_HEADER_FLAGS.MODE_X;
  if (backupActive) inclusive |= COMPACT_HEADER_FLAGS.BACKUP_ACTIVE;

  if (options.N !== undefined || forceFields.N === true) assertUint8(N, "N");
  if (options.algorithm !== undefined || forceFields.algorithm === true) {
    assertUint8(algorithm, "algorithm");
  }
  if (options.age !== undefined || forceFields.age === true) {
    if (ageBytes !== 4 && ageBytes !== 8) {
      throw compactHeaderError(
        ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
        "invalid ageBytes",
        { ageBytes }
      );
    }
  }

  if (options.backupDescriptor !== undefined) {
    assertUint8Array(options.backupDescriptor, "backupDescriptor");
  }

  const backupSize =
    options.backupSize ?? (options.backupDescriptor?.length ?? 0);
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

  if ((options.N !== undefined && N !== COMPACT_HEADER_DEFAULTS.N) || forceFields.N === true) {
    inclusive |= COMPACT_HEADER_FLAGS.N;
    optionalBytes.push(N);
  }

  if (
    (options.algorithm !== undefined && algorithm !== COMPACT_HEADER_DEFAULTS.algorithm) ||
    forceFields.algorithm === true
  ) {
    inclusive |= COMPACT_HEADER_FLAGS.ALGORITHM;
    optionalBytes.push(algorithm);
  }

  if (
    (options.age !== undefined && age !== COMPACT_HEADER_DEFAULTS.age) ||
    forceFields.age === true
  ) {
    inclusive |= COMPACT_HEADER_FLAGS.AGE;
    optionalBytes.push(...bigIntToFixedBytes(age, ageBytes));
  }

  if (hasDescriptor) {
    inclusive |= COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR;
    optionalBytes.push(...options.backupDescriptor);
  }

  const headerSize = BASE_HEADER_BYTES + optionalBytes.length;
  if (headerSize > 0xff) {
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

export function decodeCompactHeader(input) {
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
  const ageBytes = flags.hasAge
    ? optionalByteCount - knownOptionalBytes
    : 0;

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

  const N = flags.hasN
    ? readByteAtBitOffset(input, bitOffset)
    : COMPACT_HEADER_DEFAULTS.N;
  if (flags.hasN) bitOffset += 8;

  const algorithm = flags.hasAlgorithm
    ? readByteAtBitOffset(input, bitOffset)
    : COMPACT_HEADER_DEFAULTS.algorithm;
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

export function splitCompactHeaderAndBody(input) {
  const header = decodeCompactHeader(input);
  return {
    header,
    body: input.slice(header.headerSize)
  };
}
