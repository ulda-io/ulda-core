import test from "node:test";
import assert from "node:assert/strict";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

test("UldaError is an instance of Error", () => {
  const error = new UldaError(ULDA_ERROR_CODES.ULDA_INTERNAL_ERROR, "Something failed");

  assert.ok(error instanceof Error);
  assert.ok(error instanceof UldaError);
});

test("UldaError exposes name, code, message, operation, and details", () => {
  const details = { mode: "S", hash: "SHA-256", N: 5 };
  const error = new UldaError(ULDA_ERROR_CODES.ULDA_VERIFY_INVALID_GAP, "Invalid gap", {
    operation: "verify",
    details
  });

  assert.equal(error.name, "UldaError");
  assert.equal(error.code, ULDA_ERROR_CODES.ULDA_VERIFY_INVALID_GAP);
  assert.equal(error.message, "Invalid gap");
  assert.equal(error.operation, "verify");
  assert.equal(error.details, details);
});

test("toLogObject() returns a plain log-safe object", () => {
  const cause = new Error("Digest failed");
  const error = new UldaError(ULDA_ERROR_CODES.ULDA_INTERNAL_ERROR, "Hash failed", {
    operation: "sign",
    details: { mode: "S" },
    cause
  });
  const log = error.toLogObject();

  assert.equal(Object.getPrototypeOf(log), Object.prototype);
  assert.deepEqual(log, {
    name: "UldaError",
    code: ULDA_ERROR_CODES.ULDA_INTERNAL_ERROR,
    message: "Hash failed",
    operation: "sign",
    details: { mode: "S" },
    causeName: "Error",
    causeMessage: "Digest failed"
  });
});

test("toLogObject() removes private fields recursively", () => {
  const error = new UldaError(ULDA_ERROR_CODES.ULDA_FORMAT_SIZE, "Bad package", {
    operation: "verify",
    details: {
      origin: ["private"],
      blocks: ["private"],
      sigBytes: new Uint8Array([1, 2, 3]),
      bytes: new Uint8Array([4, 5, 6]),
      secret: "private",
      preimage: "private",
      raw: "private",
      privateKey: "private",
      nested: {
        mode: "S",
        origin: "private",
        items: [{ hash: "SHA-256", bytes: "private" }]
      }
    }
  });

  assert.deepEqual(error.toLogObject().details, {
    nested: {
      mode: "S",
      items: [{ hash: "SHA-256" }]
    }
  });
});

test("toLogObject() preserves safe metadata", () => {
  const details = {
    version: "1",
    packageKind: "signature",
    mode: "S",
    hash: "SHA-256",
    N: 5,
    index: 4n,
    expectedSize: 160,
    actualSize: 128,
    operation: "verify"
  };
  const error = new UldaError(ULDA_ERROR_CODES.ULDA_FORMAT_SIZE, "Bad size", {
    operation: "verify",
    details
  });

  assert.deepEqual(error.toLogObject().details, details);
});

test("ULDA_ERROR_CODES is frozen", () => {
  assert.equal(Object.isFrozen(ULDA_ERROR_CODES), true);
});
