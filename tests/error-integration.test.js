import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

test("sign() with an invalid origin package throws UldaError", async () => {
  const ulda = new UldaSign();

  await assert.rejects(
    () => ulda.sign("ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("stepUp() with an invalid origin package throws UldaError", () => {
  const ulda = new UldaSign();

  assert.throws(
    () => ulda.stepUp("ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("explicit simpleSig invalid origin package still throws sentinel UldaError", async () => {
  const ulda = new UldaSign({ sign: { pack: "simpleSig" } });

  await assert.rejects(
    () => ulda.sign("ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SENTINEL)
  );
});

test("verify() with invalid witness input throws UldaError", async () => {
  const ulda = new UldaSign();

  await assert.rejects(
    () => ulda.verify("ff", "ff"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_FORMAT_SIZE)
  );
});

test("Missing external hasher throws UldaError", async () => {
  const ulda = new UldaSign({ sign: { hash: "BLAKE3" } });
  const origin = ulda.New();

  await assert.rejects(
    () => ulda.sign(origin),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_NOT_REGISTERED)
  );
});

test("Custom hasher with unsupported output throws UldaError", async () => {
  const ulda = new UldaSign({
    sign: {
      hash: "CUSTOM",
      func: async() => "abc",
      output: "weird"
    }
  });
  const origin = ulda.New();

  await assert.rejects(
    () => ulda.sign(origin),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_OUTPUT_UNSUPPORTED)
  );
});

test("Custom hasher with size mismatch throws UldaError", async () => {
  const ulda = new UldaSign({
    sign: {
      hash: "CUSTOM",
      originSize: 256,
      func: async() => new Uint8Array([1]),
      output: "bytes"
    }
  });
  const origin = ulda.New();

  await assert.rejects(
    () => ulda.sign(origin),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_SIZE_MISMATCH)
  );
});

test("Existing incompatible but valid witnesses still return false", async () => {
  const sMode = new UldaSign({ sign: { mode: "S", N: 5 } });
  const xMode = new UldaSign({ sign: { mode: "X", N: 5 } });

  const sOrigin0 = sMode.New();
  const sSig0 = await sMode.sign(sOrigin0);
  const xOrigin0 = xMode.New();
  const xSig1 = await xMode.sign(xMode.stepUp(xOrigin0));

  assert.equal(await sMode.verify(sSig0, xSig1), false);
});
