import test from "node:test";
import assert from "node:assert/strict";
import {
  COMPACT_HEADER_DEFAULTS,
  COMPACT_HEADER_FLAGS,
  decodeCompactHeader,
  encodeCompactHeader,
  splitCompactHeaderAndBody
} from "../src/codecs/compactHeader.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

function toArray(u8) {
  return Array.from(u8);
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

function manualHeader(headerSize, inclusive, optional = []) {
  const header = new Uint8Array(headerSize);
  header[0] = headerSize >>> 4;
  header[1] = ((headerSize & 0x0f) << 4) | (inclusive >>> 4);
  header[2] = (inclusive & 0x0f) << 4;

  let bitOffset = 20;
  for (const byte of optional) {
    for (let i = 0; i < 8; i++) {
      const bit = (byte >>> (7 - i)) & 1;
      const bitIndex = bitOffset + i;
      if (bit) header[bitIndex >>> 3] |= 1 << (7 - (bitIndex & 7));
    }
    bitOffset += 8;
  }
  return header;
}

test("minimal compact header encodes to exactly 3 bytes and decodes defaults", () => {
  const header = encodeCompactHeader();
  const decoded = decodeCompactHeader(header);

  assert.deepEqual(toArray(header), [0x00, 0x30, 0x00]);
  assert.equal(decoded.headerSize, 3);
  assert.equal(decoded.bodyOffset, 3);
  assert.equal(decoded.inclusive, 0);
  assert.equal(decoded.N, COMPACT_HEADER_DEFAULTS.N);
  assert.equal(decoded.algorithm, COMPACT_HEADER_DEFAULTS.algorithm);
  assert.equal(decoded.mode, COMPACT_HEADER_DEFAULTS.mode);
  assert.equal(decoded.age, COMPACT_HEADER_DEFAULTS.age);
  assert.equal(decoded.ageBytes, 0);
  assert.equal(decoded.backupSize, 0);
  assert.deepEqual(toArray(decoded.backupDescriptor), []);
});

test("compact header with N field round-trips", () => {
  const decoded = decodeCompactHeader(encodeCompactHeader({ N: 4 }));

  assert.equal(decoded.inclusive & COMPACT_HEADER_FLAGS.N, COMPACT_HEADER_FLAGS.N);
  assert.equal(decoded.N, 4);
});

test("compact header with algorithm field round-trips", () => {
  const decoded = decodeCompactHeader(encodeCompactHeader({ algorithm: 4 }));

  assert.equal(
    decoded.inclusive & COMPACT_HEADER_FLAGS.ALGORITHM,
    COMPACT_HEADER_FLAGS.ALGORITHM
  );
  assert.equal(decoded.algorithm, 4);
});

test("compact header with mode X round-trips", () => {
  const decoded = decodeCompactHeader(encodeCompactHeader({ mode: "X" }));

  assert.equal(decoded.inclusive & COMPACT_HEADER_FLAGS.MODE_X, COMPACT_HEADER_FLAGS.MODE_X);
  assert.equal(decoded.mode, "X");
});

test("compact header with 4-byte age round-trips", () => {
  const decoded = decodeCompactHeader(encodeCompactHeader({ age: 250n, ageBytes: 4 }));

  assert.equal(decoded.inclusive & COMPACT_HEADER_FLAGS.AGE, COMPACT_HEADER_FLAGS.AGE);
  assert.equal(decoded.age, 250n);
  assert.equal(decoded.ageBytes, 4);
});

test("compact header with 8-byte age round-trips", () => {
  const age = 0x1_0000_0000n;
  const decoded = decodeCompactHeader(encodeCompactHeader({ age, ageBytes: 8 }));

  assert.equal(decoded.age, age);
  assert.equal(decoded.ageBytes, 8);
});

test("compact header with backupActive only round-trips", () => {
  const decoded = decodeCompactHeader(encodeCompactHeader({ backupActive: true }));

  assert.equal(
    decoded.inclusive & COMPACT_HEADER_FLAGS.BACKUP_ACTIVE,
    COMPACT_HEADER_FLAGS.BACKUP_ACTIVE
  );
  assert.equal(decoded.flags.backupActive, true);
  assert.equal(decoded.flags.hasBackupDescriptor, false);
  assert.deepEqual(toArray(decoded.backupDescriptor), []);
});

test("compact header with backup descriptor transports bytes without interpretation", () => {
  const descriptor = Uint8Array.of(1, 2, 3);
  const decoded = decodeCompactHeader(encodeCompactHeader({ backupDescriptor: descriptor }));

  assert.equal(
    decoded.inclusive & COMPACT_HEADER_FLAGS.BACKUP_SIZE,
    COMPACT_HEADER_FLAGS.BACKUP_SIZE
  );
  assert.equal(
    decoded.inclusive & COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR,
    COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR
  );
  assert.equal(decoded.backupSize, 3);
  assert.deepEqual(toArray(decoded.backupDescriptor), [1, 2, 3]);
});

test("compact header with all current optional fields round-trips", () => {
  const descriptor = Uint8Array.of(7, 8, 9);
  const age = 123456789n;
  const decoded = decodeCompactHeader(
    encodeCompactHeader({
      N: 6,
      algorithm: 5,
      mode: "X",
      age,
      ageBytes: 4,
      backupActive: true,
      backupDescriptor: descriptor
    })
  );

  assert.equal(decoded.N, 6);
  assert.equal(decoded.algorithm, 5);
  assert.equal(decoded.mode, "X");
  assert.equal(decoded.age, age);
  assert.equal(decoded.ageBytes, 4);
  assert.equal(decoded.backupSize, 3);
  assert.deepEqual(toArray(decoded.backupDescriptor), [7, 8, 9]);
  assert.equal(decoded.flags.backupActive, true);
});

test("splitCompactHeaderAndBody returns the body at headerSize", () => {
  const header = encodeCompactHeader({ N: 4 });
  const input = new Uint8Array([...header, 9, 8, 7]);
  const split = splitCompactHeaderAndBody(input);

  assert.equal(split.header.headerSize, header.length);
  assert.deepEqual(toArray(split.body), [9, 8, 7]);
});

test("invalid prefix sentinel throws UldaError with ULDA_FORMAT_SENTINEL", () => {
  const header = encodeCompactHeader();
  header[0] = 0x10;

  assert.throws(
    () => decodeCompactHeader(header),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL)
  );
});

test("invalid suffix sentinel throws UldaError with ULDA_FORMAT_SENTINEL", () => {
  const header = encodeCompactHeader();
  header[2] = 0x01;

  assert.throws(
    () => decodeCompactHeader(header),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL)
  );
});

test("headerSize smaller than 3 throws UldaError", () => {
  assert.throws(
    () => decodeCompactHeader(Uint8Array.of(0x00, 0x20, 0x00)),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_HEADER)
  );
});

test("headerSize larger than input length throws UldaError", () => {
  assert.throws(
    () => decodeCompactHeader(Uint8Array.of(0x00, 0x40, 0x00)),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("backup descriptor flag without backupSize flag throws UldaError", () => {
  assert.throws(
    () => decodeCompactHeader(manualHeader(3, COMPACT_HEADER_FLAGS.BACKUP_DESCRIPTOR)),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_HEADER)
  );
});

test("age field with inferred length other than 4 or 8 throws UldaError", () => {
  assert.throws(
    () => decodeCompactHeader(manualHeader(4, COMPACT_HEADER_FLAGS.AGE, [0])),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_HEADER)
  );
});

test("encoder rejects invalid mode", () => {
  assert.throws(
    () => encodeCompactHeader({ mode: "Z" }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("encoder rejects age that does not fit into 4 bytes", () => {
  assert.throws(
    () => encodeCompactHeader({ age: 0x1_0000_0000n, ageBytes: 4 }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("encoder rejects headerSize larger than 255", () => {
  assert.throws(
    () => encodeCompactHeader({ backupDescriptor: new Uint8Array(253) }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});
