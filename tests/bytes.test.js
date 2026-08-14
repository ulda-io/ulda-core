import test from "node:test";
import assert from "node:assert/strict";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  equalBytes,
  exportBytes,
  guessToBytes,
  hexToBytes,
  importBytes,
  indexToBytes
} from "../src/bytes/index.js";

function toArray(u8) {
  return Array.from(u8);
}

test("bytesToHex and hexToBytes round-trip", () => {
  const bytes = new Uint8Array([0, 1, 15, 16, 255]);
  const hex = bytesToHex(bytes);

  assert.equal(hex, "00010f10ff");
  assert.deepEqual(toArray(hexToBytes(hex)), toArray(bytes));
});

test("bytesToBase64 and base64ToBytes round-trip", () => {
  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const base64 = bytesToBase64(bytes);

  assert.deepEqual(toArray(base64ToBytes(base64)), toArray(bytes));
});

test("guessToBytes detects hex for even-length hex strings", () => {
  assert.deepEqual(toArray(guessToBytes("0a10ff")), [10, 16, 255]);
});

test("indexToBytes(0n) returns [0]", () => {
  assert.deepEqual(toArray(indexToBytes(0n)), [0]);
});

test("indexToBytes(256n) returns [1, 0]", () => {
  assert.deepEqual(toArray(indexToBytes(256n)), [1, 0]);
});

test("concatBytes concatenates Uint8Arrays", () => {
  const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));

  assert.deepEqual(toArray(out), [1, 2, 3, 4, 5]);
});

test("equalBytes compares byte contents", () => {
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
});

test("exportBytes supports hex, base64, and bytes", () => {
  const bytes = new Uint8Array([1, 2, 3]);

  assert.equal(exportBytes(bytes, "hex"), "010203");
  assert.equal(exportBytes(bytes, "base64"), "AQID");
  assert.equal(exportBytes(bytes, "bytes"), bytes);
});

test("importBytes supports hex, base64, and Uint8Array input", () => {
  const bytes = new Uint8Array([1, 2, 3]);

  assert.deepEqual(toArray(importBytes("010203", "hex")), [1, 2, 3]);
  assert.deepEqual(toArray(importBytes("AQID", "base64")), [1, 2, 3]);
  assert.equal(importBytes(bytes, "bytes"), bytes);
});

test("Unknown export format defaults to hex", () => {
  assert.equal(exportBytes(new Uint8Array([10, 11]), "weird"), "0a0b");
});

test("Unknown import format uses guess behavior", () => {
  assert.deepEqual(toArray(importBytes("0a0b", "weird")), [10, 11]);
  assert.deepEqual(toArray(importBytes("AQID", "weird")), [1, 2, 3]);
});
