import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import {
  createDecoderFromEncoder,
  createDefaultEncoder,
  normalizeConfig,
  registerCustomHasher
} from "../src/config/index.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function fixedHasher() {
  return async() => new Uint8Array(32);
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

async function assertTransitionVerifies(ulda) {
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
}

test("normalizeConfig() returns current defaults", () => {
  const cfg = normalizeConfig();

  assert.equal(cfg.version, "1");
  assert.equal(cfg.fmt.export, "hex");
  assert.equal(cfg.sign.N, 5);
  assert.equal(cfg.sign.mode, "S");
  assert.equal(cfg.sign.hash, "SHA-256");
  assert.equal(cfg.sign.originSize, 256);
  assert.equal(cfg.sign.pack, "compactV1");
  assert.equal(cfg.sign.ageBytes, 4);
});

test("normalizeConfig(cfg) respects overrides", () => {
  const cfg = normalizeConfig({
    version: "2",
    fmt: { export: "bytes" },
    sign: {
      N: 7,
      mode: "X",
      hash: "BLAKE3",
      originSize: 128,
      pack: "customPack",
      ageBytes: 4
    }
  });

  assert.equal(cfg.version, "2");
  assert.equal(cfg.fmt.export, "bytes");
  assert.equal(cfg.sign.N, 7);
  assert.equal(cfg.sign.mode, "X");
  assert.equal(cfg.sign.hash, "BLAKE3");
  assert.equal(cfg.sign.originSize, 128);
  assert.equal(cfg.sign.pack, "customPack");
  assert.equal(cfg.sign.ageBytes, 4);
});

test("normalizeConfig(cfg) rejects unsupported ageBytes", () => {
  assert.throws(
    () => normalizeConfig({ sign: { ageBytes: 8 } }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("normalizeConfig(cfg) preserves externalHashers object reference", () => {
  const externalHashers = {};

  assert.equal(normalizeConfig({ externalHashers }).externalHashers, externalHashers);
});

test("createDefaultEncoder() returns a fresh mutable copy", () => {
  const a = createDefaultEncoder();
  const b = createDefaultEncoder();

  a.algorithm.TEST = 99;

  assert.equal(b.algorithm.TEST, undefined);
});

test("createDecoderFromEncoder() maps default algorithm codes correctly", () => {
  const decoder = createDecoderFromEncoder(createDefaultEncoder());

  assert.equal(decoder.algorithm[2], "SHA-256");
  assert.equal(decoder.algorithm[7], "BLAKE3");
  assert.equal(decoder.algorithm[0xff], "CUSTOM");
});

test("registerCustomHasher() does nothing when no function is provided", () => {
  const config = normalizeConfig();
  const encoder = createDefaultEncoder();
  const decoder = createDecoderFromEncoder(encoder);

  assert.equal(registerCustomHasher({ cfg: {}, config, encoder, decoder }), undefined);
  assert.deepEqual(config.externalHashers, {});
});

test('registerCustomHasher() with no explicit hash sets config.sign.hash to "CUSTOM"', () => {
  const config = normalizeConfig({ sign: { func: fixedHasher() } });
  const encoder = createDefaultEncoder();
  const decoder = createDecoderFromEncoder(encoder);
  const result = registerCustomHasher({
    cfg: { sign: { func: fixedHasher() } },
    config,
    encoder,
    decoder
  });

  assert.deepEqual(result, { id: "CUSTOM" });
  assert.equal(config.sign.hash, "CUSTOM");
  assert.equal(decoder.algorithm[0xff], "CUSTOM");
});

test('registerCustomHasher() with "MY-HASH" registers external hasher and 0xff maps', () => {
  const config = normalizeConfig({ sign: { hash: "MY-HASH" } });
  const encoder = createDefaultEncoder();
  const decoder = createDecoderFromEncoder(encoder);
  registerCustomHasher({
    cfg: { sign: { hash: "MY-HASH", func: fixedHasher(), output: "bytes", originSize: 256 } },
    config,
    encoder,
    decoder
  });

  assert.equal(typeof config.externalHashers["MY-HASH"].fn, "function");
  assert.equal(encoder.algorithm["MY-HASH"], 0xff);
  assert.equal(decoder.algorithm[0xff], "MY-HASH");
});

test('registerCustomHasher() with "BLAKE3" keeps original wire code', () => {
  const config = normalizeConfig({ sign: { hash: "BLAKE3" } });
  const encoder = createDefaultEncoder();
  const decoder = createDecoderFromEncoder(encoder);
  registerCustomHasher({
    cfg: { sign: { hash: "BLAKE3", func: fixedHasher(), output: "bytes", originSize: 256 } },
    config,
    encoder,
    decoder
  });

  assert.equal(encoder.algorithm.BLAKE3, 7);
  assert.equal(typeof config.externalHashers.BLAKE3.fn, "function");
});

test("Public API regression still works", async () => {
  await assertTransitionVerifies(new UldaSign());
});

test('Custom "MY-HASH" still works through public API and decodes origin alg', async () => {
  const ulda = new UldaSign({
    sign: { hash: "MY-HASH", func: fixedHasher(), output: "bytes", originSize: 256 }
  });
  const origin = ulda.New();

  assert.equal(ulda.codec.decodeOrigin(origin).alg, "MY-HASH");
  await assertTransitionVerifies(ulda);
});

test("Compatibility actions facade regression still works", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.actions.Sign(origin0);
  const origin1 = ulda.actions.StepUp(origin0);
  const sig1 = await ulda.actions.Sign(origin1);

  assert.equal(await ulda.actions.Verify(sig0, sig1), true);
});
