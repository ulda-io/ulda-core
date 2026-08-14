import test from "node:test";
import assert from "node:assert/strict";
import {
  ULDA_CODEC_PACKS,
  createCodecForPack,
  normalizeCodecPack
} from "../src/codecs/registry.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

test("normalizeCodecPack(undefined) returns compactV1", () => {
  assert.equal(normalizeCodecPack(undefined), ULDA_CODEC_PACKS.COMPACT_V1);
});

test("normalizeCodecPack(null) returns compactV1", () => {
  assert.equal(normalizeCodecPack(null), ULDA_CODEC_PACKS.COMPACT_V1);
});

test("normalizeCodecPack(simpleSig) returns simpleSig", () => {
  assert.equal(normalizeCodecPack("simpleSig"), ULDA_CODEC_PACKS.SIMPLE_SIG);
});

test("normalizeCodecPack(v1) maps to simpleSig", () => {
  assert.equal(normalizeCodecPack("v1"), ULDA_CODEC_PACKS.SIMPLE_SIG);
});

test("normalizeCodecPack(compactV1) returns compactV1", () => {
  assert.equal(normalizeCodecPack("compactV1"), ULDA_CODEC_PACKS.COMPACT_V1);
});

test("normalizeCodecPack rejects unknown packs", () => {
  assert.throws(
    () => normalizeCodecPack("unknown"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("createCodecForPack(simpleSig) returns v1 codec", () => {
  const selection = createCodecForPack({ pack: "simpleSig" });

  assert.equal(selection.id, ULDA_CODEC_PACKS.SIMPLE_SIG);
  assert.equal(typeof selection.codec.makeHeader, "function");
  assert.equal(typeof selection.codec.encodeOrigin, "function");
  assert.equal(typeof selection.codec.decodeWitness, "function");
});

test("createCodecForPack(undefined) returns compactV1 codec", () => {
  const selection = createCodecForPack({});

  assert.equal(selection.id, ULDA_CODEC_PACKS.COMPACT_V1);
  assert.equal(typeof selection.codec.encodeHeader, "function");
  assert.equal(typeof selection.codec.makeHeader, "undefined");
});

test("createCodecForPack(compactV1) returns compactV1 codec", () => {
  const selection = createCodecForPack({ pack: "compactV1" });

  assert.equal(selection.id, ULDA_CODEC_PACKS.COMPACT_V1);
  assert.equal(typeof selection.codec.encodeHeader, "function");
  assert.equal(typeof selection.codec.makeHeader, "undefined");
  assert.equal(typeof selection.codec.encodeOrigin, "function");
  assert.equal(typeof selection.codec.decodeWitness, "function");
});
