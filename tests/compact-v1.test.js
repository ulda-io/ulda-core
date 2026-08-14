import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { concatBytes } from "../src/bytes/index.js";
import { COMPACT_HEADER_FLAGS, encodeCompactHeader } from "../src/codecs/compactHeader.js";
import { createCompactV1Codec } from "../src/codecs/compactV1.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function toArray(u8) {
  return Array.from(u8);
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

function defaultOriginBlocks() {
  return [
    Uint8Array.of(1, 2),
    Uint8Array.of(3, 4),
    Uint8Array.of(5, 6),
    Uint8Array.of(7, 8),
    Uint8Array.of(9, 10)
  ];
}

test("compactV1 encodeOrigin and decodeOrigin round-trip with defaults", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const origin = defaultOriginBlocks();
  const encoded = codec.encodeOrigin({ origin }, 0n);
  const decoded = codec.decodeOrigin(encoded);

  assert.equal(decoded.header.headerSize, 3);
  assert.equal(decoded.N, 5);
  assert.equal(decoded.mode, "S");
  assert.equal(decoded.alg, "SHA-256");
  assert.equal(decoded.index, 0n);
  assert.equal(decoded.blockLen, 2);
  assert.deepEqual(decoded.origin.map(toArray), origin.map(toArray));
});

test("default compactV1 origin header uses the minimal compact header", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const encoded = codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n);
  const decoded = codec.decodeOrigin(encoded);

  assert.equal(decoded.header.headerSize, 3);
  assert.deepEqual(toArray(encoded.slice(0, decoded.header.headerSize)), [0x00, 0x30, 0x00]);
});

test("compactV1 encodeOrigin and decodeOrigin with non-default N", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const origin = [
    Uint8Array.of(1),
    Uint8Array.of(2),
    Uint8Array.of(3),
    Uint8Array.of(4)
  ];
  const decoded = codec.decodeOrigin(codec.encodeOrigin({ origin }, 0n, { N: 4 }));

  assert.equal(decoded.N, 4);
  assert.equal(decoded.header.inclusive & COMPACT_HEADER_FLAGS.N, COMPACT_HEADER_FLAGS.N);
});

test("compactV1 encodeOrigin and decodeOrigin with mode X", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const decoded = codec.decodeOrigin(
    codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n, { mode: "X" })
  );

  assert.equal(decoded.mode, "X");
  assert.equal(decoded.header.inclusive & COMPACT_HEADER_FLAGS.MODE_X, COMPACT_HEADER_FLAGS.MODE_X);
});

test("compactV1 encodeOrigin and decodeOrigin with SHA-512", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const decoded = codec.decodeOrigin(
    codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n, { hash: "SHA-512" })
  );

  assert.equal(decoded.alg, "SHA-512");
  assert.equal(
    decoded.header.inclusive & COMPACT_HEADER_FLAGS.ALGORITHM,
    COMPACT_HEADER_FLAGS.ALGORITHM
  );
});

test("compactV1 encodeOrigin and decodeOrigin with 4-byte age", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const decoded = codec.decodeOrigin(codec.encodeOrigin({ origin: defaultOriginBlocks() }, 250n));

  assert.equal(decoded.index, 250n);
  assert.equal(decoded.header.ageBytes, 4);
});

test("compactV1 encodes age 1 with canonical 4-byte age", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const decoded = codec.decodeOrigin(codec.encodeOrigin({ origin: defaultOriginBlocks() }, 1n));

  assert.equal(decoded.index, 1n);
  assert.equal(decoded.header.ageBytes, 4);
  assert.equal(decoded.header.inclusive & COMPACT_HEADER_FLAGS.AGE, COMPACT_HEADER_FLAGS.AGE);
});

test("compactV1 rejects 8-byte age encoding", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });

  assert.throws(
    () => codec.encodeOrigin({ origin: defaultOriginBlocks() }, 1n, { ageBytes: 8 }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("compactV1 rejects age larger than uint32", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const index = 0x1_0000_0000n;

  assert.throws(
    () => codec.encodeOrigin({ origin: defaultOriginBlocks() }, index),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("compactV1 rejects decoded 8-byte age packages", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const header = encodeCompactHeader({ age: 0x1_0000_0000n, ageBytes: 8 });
  const pkg = new Uint8Array([...header, ...new Uint8Array(10)]);

  assert.throws(
    () => codec.decodeOrigin(pkg),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_HEADER)
  );
});

test("compactV1 encodeWitness and decodeWitness round-trip", () => {
  const codec = createCompactV1Codec({
    getExportFormat: () => "bytes",
    getOriginSize: () => 256
  });
  const sigBytes = Uint8Array.from({ length: 40 }, (_, i) => i + 1);
  const decoded = codec.decodeWitness(
    codec.encodeWitness(sigBytes, {
      index: 3n,
      N: 5,
      mode: "S",
      hash: "SHA-256"
    })
  );

  assert.equal(decoded.N, 5);
  assert.equal(decoded.index, 3n);
  assert.equal(decoded.originLen, 32);
  assert.equal(decoded.blkLen, 2);
  assert.deepEqual(toArray(decoded.sigBytes), toArray(sigBytes));
  assert.deepEqual(decoded.blocks.map(toArray), [
    toArray(sigBytes.slice(0, 32)),
    [33, 34],
    [35, 36],
    [37, 38],
    [39, 40]
  ]);
});

test("compactV1 packWitness delegates to encodeWitness format", () => {
  const codec = createCompactV1Codec();
  const sigBytes = Uint8Array.of(1, 2, 3, 4);
  const meta = { index: 1n, N: 2, mode: "S", hash: "SHA-256" };

  assert.equal(codec.packWitness(sigBytes, meta), codec.encodeWitness(sigBytes, meta));
});

test("compactV1 splitWitnessBlocks supports p.blocks shortcut", () => {
  const codec = createCompactV1Codec();
  const blocks = [Uint8Array.of(1), Uint8Array.of(2)];

  assert.equal(codec.splitWitnessBlocks({ blocks }), blocks);
});

test("compactV1 supports export format hex", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "hex" });
  const encoded = codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n);

  assert.equal(typeof encoded, "string");
  assert.deepEqual(codec.decodeOrigin(encoded).origin.map(toArray), defaultOriginBlocks().map(toArray));
});

test("compactV1 supports export format base64", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "base64" });
  const encoded = codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n);

  assert.equal(typeof encoded, "string");
  assert.deepEqual(codec.decodeOrigin(encoded).origin.map(toArray), defaultOriginBlocks().map(toArray));
});

test("compactV1 supports export format bytes", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const encoded = codec.encodeOrigin({ origin: defaultOriginBlocks() }, 0n);

  assert.ok(encoded instanceof Uint8Array);
  assert.deepEqual(codec.decodeOrigin(encoded).origin.map(toArray), defaultOriginBlocks().map(toArray));
});

test("compactV1 transports backup descriptor without interpreting it", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const descriptor = Uint8Array.of(8, 7, 6);
  const decoded = codec.decodeOrigin(
    codec.encodeOrigin(
      { origin: defaultOriginBlocks() },
      0n,
      {
        backupActive: true,
        backupDescriptor: descriptor
      }
    )
  );

  assert.equal(decoded.header.flags.backupActive, true);
  assert.equal(decoded.header.backupSize, 3);
  assert.deepEqual(toArray(decoded.header.backupDescriptor), [8, 7, 6]);
  assert.deepEqual(decoded.origin.map(toArray), defaultOriginBlocks().map(toArray));
});

test("compactV1 invalid origin body division throws UldaError", () => {
  const codec = createCompactV1Codec({ getExportFormat: () => "bytes" });
  const pkg = concatBytes(codec.encodeHeader({ N: 2 }), Uint8Array.of(1, 2, 3));

  assert.throws(
    () => codec.decodeOrigin(pkg),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_BODY_DIVISION)
  );
});

test("compactV1 invalid witness body size throws UldaError", () => {
  const codec = createCompactV1Codec({
    getExportFormat: () => "bytes",
    getOriginSize: () => 256
  });
  const pkg = concatBytes(codec.encodeHeader({ N: 5 }), Uint8Array.of(1, 2, 3));

  assert.throws(
    () => codec.decodeWitness(pkg),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("compactV1 does not affect default UldaSign public API", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});
