import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { base64ToBytes } from "../src/bytes/index.js";
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

async function signedAt(ulda, origin) {
  return {
    origin,
    sig: await ulda.sign(origin)
  };
}

test("default UldaSign works and uses compactV1", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(ulda.codecPack, "compactV1");
  assert.equal(typeof ulda.codec.encodeHeader, "function");
  assert.equal(typeof ulda.codec.makeHeader, "undefined");
  assert.equal(ulda.codec.decodeOrigin(origin0).index, 0n);
  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});

test("compactV1 runtime selects compactV1 pack", () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });

  assert.equal(ulda.codecPack, "compactV1");
  assert.equal(typeof ulda.codec.encodeHeader, "function");
});

test("explicit simpleSig runtime still works", async () => {
  const ulda = new UldaSign({ sign: { pack: "simpleSig" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(ulda.codecPack, "simpleSig");
  assert.equal(typeof ulda.codec.makeHeader, "function");
  assert.equal(ulda.codec.decodeOrigin(origin0).bytes[0], 0);
  assert.equal(ulda.codec.decodeOrigin(origin0).bytes[1], 7);
  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});

test("compactV1 runtime full S flow works", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("compactV1 runtime rejects reverse verify order", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});

for (const pack of ["compactV1", "simpleSig"]) {
  for (const mode of ["S", "X"]) {
    test(`${pack} mode ${mode} keeps public and legacy verify APIs directed`, async () => {
      const ulda = new UldaSign({ sign: { pack, mode } });
      const origin0 = ulda.New();
      const sig0 = await ulda.sign(origin0);
      const sig1 = await ulda.sign(ulda.stepUp(origin0));
      const previousWitness = ulda.actions.import.signature(sig0);
      const candidateWitness = ulda.actions.import.signature(sig1);
      const verifyMode = mode === "S" ? ulda.actions.VerifyS : ulda.actions.VerifyX;

      assert.equal(await ulda.verify(sig0, sig1), true);
      assert.equal(await ulda.verify(sig1, sig0), false);
      assert.equal(await ulda.verify(sig0, sig0), false);
      assert.equal(await ulda.actions.Verify(sig0, sig1), true);
      assert.equal(await ulda.actions.Verify(sig1, sig0), false);
      assert.equal(await verifyMode(previousWitness, candidateWitness), true);
      assert.equal(await verifyMode(candidateWitness, previousWitness), false);
      assert.equal(await verifyMode(previousWitness, previousWitness), false);
    });
  }
}

test("compactV1 runtime mode X verifies one step and rejects two steps", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1", mode: "X" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);
  const origin2 = ulda.stepUp(origin1);
  const sig2 = await ulda.sign(origin2);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig0, sig2), false);
});

test("compactV1 runtime S skip behavior matches current gap rules", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1", N: 5 } });
  let origin = ulda.New();
  const sig0 = await ulda.sign(origin);
  let sig4;
  let sig5;

  for (let i = 1; i <= 5; i++) {
    origin = ulda.stepUp(origin);
    const sig = await ulda.sign(origin);
    if (i === 4) sig4 = sig;
    if (i === 5) sig5 = sig;
  }

  assert.equal(await ulda.verify(sig0, sig4), true);
  assert.equal(await ulda.verify(sig0, sig5), false);
});

test("compactV1 runtime encodes and decodes age as index", () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const origin0 = ulda.New(0n);
  const origin1 = ulda.stepUp(origin0);
  const origin2 = ulda.stepUp(origin1);

  assert.equal(ulda.codec.decodeOrigin(origin0).index, 0n);
  assert.equal(ulda.codec.decodeOrigin(origin1).index, 1n);
  assert.equal(ulda.codec.decodeOrigin(origin2).index, 2n);
});

test("compactV1 runtime supports max uint32 age", () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const index = 4294967295n;
  const origin = ulda.New(index);
  const decoded = ulda.codec.decodeOrigin(origin);

  assert.equal(decoded.index, index);
  assert.equal(decoded.header.ageBytes, 4);
});

test("compactV1 runtime rejects ageBytes 8", () => {
  assert.throws(
    () => new UldaSign({ sign: { pack: "compactV1", ageBytes: 8 } }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("compactV1 runtime rejects age larger than uint32", () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });

  assert.throws(
    () => ulda.New(4294967296n),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("compactV1 runtime supports hex export format", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" }, fmt: { export: "hex" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));

  assert.equal(typeof origin0, "string");
  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("compactV1 runtime supports base64 export format", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" }, fmt: { export: "base64" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));

  assert.doesNotThrow(() => base64ToBytes(origin0));
  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("compactV1 runtime supports bytes export format", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" }, fmt: { export: "bytes" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));

  assert.ok(origin0 instanceof Uint8Array);
  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("compactV1 legacy actions facades still work", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.actions.Sign(origin0);
  const origin1 = ulda.actions.StepUp(origin0);
  const sig1 = await ulda.actions.Sign(origin1);

  assert.equal(await ulda.actions.Verify(sig0, sig1), true);
});

test("compactV1 actions._hdr throws a clear UldaError", () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });

  assert.throws(
    () => ulda.actions._hdr(5, "S", "SHA-256", Uint8Array.of(0)),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("default compactV1 actions._hdr throws a clear UldaError", () => {
  const ulda = new UldaSign();

  assert.throws(
    () => ulda.actions._hdr(5, "S", "SHA-256", Uint8Array.of(0)),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_CONFIG_INVALID)
  );
});

test("explicit simpleSig actions._hdr still works", () => {
  const ulda = new UldaSign({ sign: { pack: "simpleSig" } });
  const header = ulda.actions._hdr(5, "S", "SHA-256", Uint8Array.of(0));

  assert.equal(header[0], 0);
  assert.equal(header[1], header.length);
  assert.equal(header[2], 5);
  assert.equal(header.at(-1), 0);
});

test("cross-pack compactV1 packages are not accepted as simpleSig", async () => {
  const compact = new UldaSign({ sign: { pack: "compactV1" } });
  const simple = new UldaSign({ sign: { pack: "simpleSig" } });
  const origin0 = compact.New();
  const sig0 = await compact.sign(origin0);
  const sig1 = await compact.sign(compact.stepUp(origin0));

  let accepted = false;
  try {
    accepted = await simple.verify(sig0, sig1);
  } catch (err) {
    assert.ok(err instanceof UldaError);
  }

  assert.equal(accepted, false);
});

test("backup remains outside runtime semantics", async () => {
  const ulda = new UldaSign({ sign: { pack: "compactV1" } });
  const first = await signedAt(ulda, ulda.New());
  const second = await signedAt(ulda, ulda.stepUp(first.origin));

  assert.equal(await ulda.verify(first.sig, second.sig), true);
});
