import test from "node:test";
import assert from "node:assert/strict";
import { base64ToBytes } from "../src/bytes/index.js";
import {
  createV1Codec,
  DEFAULT_V1_ENCODER,
  DEFAULT_V1_DECODER
} from "../src/codecs/v1.js";
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

test("makeHeader preserves the current v1 header shape", () => {
  const codec = createV1Codec();
  const header = codec.makeHeader(5, "S", "SHA-256", Uint8Array.of(0));

  assert.equal(header[0], 0);
  assert.equal(header[1], header.length);
  assert.equal(header[2], 5);
  assert.equal(header[3], DEFAULT_V1_ENCODER.mode.S);
  assert.equal(header[4], DEFAULT_V1_ENCODER.algorithm["SHA-256"]);
  assert.equal(header.at(-1), 0);
});

test("encodeOrigin and decodeOrigin round-trip", () => {
  const codec = createV1Codec();
  const originObj = {
    origin: [new Uint8Array([1, 2]), new Uint8Array([3, 4])]
  };
  const encoded = codec.encodeOrigin(originObj, 256n, {
    N: 2,
    mode: "S",
    hash: "SHA-256"
  });
  const decoded = codec.decodeOrigin(encoded);

  assert.equal(decoded.N, 2);
  assert.equal(decoded.mode, "S");
  assert.equal(decoded.alg, "SHA-256");
  assert.equal(decoded.index, 256n);
  assert.equal(decoded.blockLen, 2);
  assert.deepEqual(decoded.origin.map(toArray), [[1, 2], [3, 4]]);
});

test("encodeWitness and decodeWitness round-trip", () => {
  const codec = createV1Codec({ getOriginSize: () => 16 });
  const sigBytes = new Uint8Array([1, 2, 3, 4, 5, 6]);
  const encoded = codec.encodeWitness(sigBytes, {
    index: 3n,
    N: 3,
    mode: "X",
    hash: "SHA-512"
  });
  const decoded = codec.decodeWitness(encoded);

  assert.equal(decoded.N, 3);
  assert.equal(decoded.mode, "X");
  assert.equal(decoded.alg, "SHA-512");
  assert.equal(decoded.index, 3n);
  assert.equal(decoded.originLen, 2);
  assert.equal(decoded.blkLen, 2);
  assert.deepEqual(decoded.blocks.map(toArray), [[1, 2], [3, 4], [5, 6]]);
});

test("packWitness delegates to the same format as encodeWitness", () => {
  const codec = createV1Codec({ getOriginSize: () => 16 });
  const sigBytes = new Uint8Array([1, 2, 3, 4]);
  const meta = { index: 1n, N: 2, mode: "S", alg: "SHA-256" };

  assert.equal(codec.packWitness(sigBytes, meta), codec.encodeWitness(sigBytes, meta));
});

test("splitWitnessBlocks preserves current behavior", () => {
  const codec = createV1Codec();
  const existingBlocks = [new Uint8Array([9])];
  const split = codec.splitWitnessBlocks({
    originLen: 2,
    blkLen: 2,
    N: 3,
    sigBytes: new Uint8Array([1, 2, 3, 4, 5, 6])
  });

  assert.equal(codec.splitWitnessBlocks({ blocks: existingBlocks }), existingBlocks);
  assert.deepEqual(split.map(toArray), [[1, 2], [3, 4], [5, 6]]);
});

test("Codec supports export format hex", () => {
  const codec = createV1Codec({ getExportFormat: () => "hex" });
  const encoded = codec.encodeOrigin({
    origin: [new Uint8Array([1]), new Uint8Array([2])]
  }, 0n, { N: 2, mode: "S", hash: "SHA-256" });

  assert.equal(typeof encoded, "string");
  assert.deepEqual(toArray(codec.decodeOrigin(encoded).origin[0]), [1]);
});

test("Codec supports export format base64", () => {
  const codec = createV1Codec({ getExportFormat: () => "base64" });
  const encoded = codec.encodeOrigin({
    origin: [new Uint8Array([1]), new Uint8Array([2])]
  }, 0n, { N: 2, mode: "S", hash: "SHA-256" });

  assert.equal(typeof encoded, "string");
  assert.doesNotThrow(() => base64ToBytes(encoded));
  assert.deepEqual(toArray(codec.decodeOrigin(encoded).origin[1]), [2]);
});

test("Codec supports export format bytes", () => {
  const codec = createV1Codec({ getExportFormat: () => "bytes" });
  const encoded = codec.encodeOrigin({
    origin: [new Uint8Array([1]), new Uint8Array([2])]
  }, 0n, { N: 2, mode: "S", hash: "SHA-256" });

  assert.ok(encoded instanceof Uint8Array);
  assert.deepEqual(toArray(codec.decodeOrigin(encoded).origin[0]), [1]);
});

test("decodeOrigin throws UldaError with ULDA_FORMAT_SENTINEL for invalid sentinel", () => {
  const codec = createV1Codec();

  assert.throws(
    () => codec.decodeOrigin("ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL)
  );
});

test("decodeWitness throws UldaError with ULDA_FORMAT_SIZE for invalid witness sizes", () => {
  const codec = createV1Codec();

  assert.throws(
    () => codec.decodeWitness("ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("DEFAULT_V1_DECODER matches default wire codes", () => {
  assert.equal(DEFAULT_V1_DECODER.mode[1], "S");
  assert.equal(DEFAULT_V1_DECODER.mode[2], "X");
  assert.equal(DEFAULT_V1_DECODER.algorithm[2], "SHA-256");
  assert.equal(DEFAULT_V1_DECODER.algorithm[0xff], "CUSTOM");
});
