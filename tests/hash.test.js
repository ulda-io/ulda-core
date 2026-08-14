import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import { bytesToBase64, bytesToHex } from "../src/bytes/index.js";
import { createHashProvider, WEB_CRYPTO_ALGORITHMS } from "../src/crypto/hash.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

const cryptoImpl = globalThis.crypto ?? webcrypto;

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

test("WEB_CRYPTO_ALGORITHMS is frozen", () => {
  assert.equal(Object.isFrozen(WEB_CRYPTO_ALGORITHMS), true);
});

test('hash() with "SHA-256" returns the known digest of "abc"', async () => {
  const provider = createHashProvider({ cryptoImpl });
  const input = new TextEncoder().encode("abc");
  const digest = await provider.hash(input, "SHA-256");

  assert.equal(
    bytesToHex(digest),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});

test('hashIter(u8, 0, "SHA-256") returns the original bytes unchanged', async () => {
  const provider = createHashProvider({ cryptoImpl });
  const input = new Uint8Array([1, 2, 3]);

  assert.equal(await provider.hashIter(input, 0, "SHA-256"), input);
});

test('hashIter(u8, 2, "SHA-256") equals manually applying hash twice', async () => {
  const provider = createHashProvider({ cryptoImpl });
  const input = new Uint8Array([1, 2, 3]);
  const once = await provider.hash(input, "SHA-256");
  const twice = await provider.hash(once, "SHA-256");

  assert.deepEqual(await provider.hashIter(input, 2, "SHA-256"), twice);
});

test('External hasher with "bytes" output returns bytes', async () => {
  const provider = createHashProvider({
    externalHashers: {
      CUSTOM: { fn: async() => new Uint8Array([1, 2, 3]), output: "bytes" }
    },
    cryptoImpl
  });

  assert.deepEqual(await provider.hash(new Uint8Array([9]), "CUSTOM"), new Uint8Array([1, 2, 3]));
});

test('External hasher with "hex" output returns parsed bytes', async () => {
  const provider = createHashProvider({
    externalHashers: {
      CUSTOM: { fn: async() => "0102ff", output: "hex" }
    },
    cryptoImpl
  });

  assert.deepEqual(await provider.hash(new Uint8Array([9]), "CUSTOM"), new Uint8Array([1, 2, 255]));
});

test('External hasher with "base64" output returns parsed bytes', async () => {
  const provider = createHashProvider({
    externalHashers: {
      CUSTOM: { fn: async() => bytesToBase64(new Uint8Array([1, 2, 3])), output: "base64" }
    },
    cryptoImpl
  });

  assert.deepEqual(await provider.hash(new Uint8Array([9]), "CUSTOM"), new Uint8Array([1, 2, 3]));
});

test("Missing external hasher throws UldaError", async () => {
  const provider = createHashProvider({ cryptoImpl });

  await assert.rejects(
    () => provider.hash(new Uint8Array([1]), "BLAKE3"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_NOT_REGISTERED)
  );
});

test("Unsupported external hasher output throws UldaError", async () => {
  const provider = createHashProvider({
    externalHashers: {
      CUSTOM: { fn: async() => "abc", output: "weird" }
    },
    cryptoImpl
  });

  await assert.rejects(
    () => provider.hash(new Uint8Array([1]), "CUSTOM"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_OUTPUT_UNSUPPORTED)
  );
});

test("External hasher size mismatch throws UldaError", async () => {
  const provider = createHashProvider({
    externalHashers: {
      CUSTOM: { fn: async() => new Uint8Array([1]), output: "bytes", size: 256 }
    },
    cryptoImpl
  });

  await assert.rejects(
    () => provider.hash(new Uint8Array([1]), "CUSTOM"),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_HASHER_SIZE_MISMATCH)
  );
});

test("External hasher with cdn loads once and marks ready", async () => {
  const calls = [];
  const ext = {
    cdn: "https://example.test/hash.js",
    ready: false,
    fn: async() => new Uint8Array([7]),
    output: "bytes"
  };
  const provider = createHashProvider({
    externalHashers: { CUSTOM: ext },
    loadScriptOnce: async src => calls.push(src),
    cryptoImpl
  });

  assert.deepEqual(await provider.hash(new Uint8Array([1]), "CUSTOM"), new Uint8Array([7]));
  assert.deepEqual(await provider.hash(new Uint8Array([2]), "CUSTOM"), new Uint8Array([7]));
  assert.deepEqual(calls, ["https://example.test/hash.js"]);
  assert.equal(ext.ready, true);
});
