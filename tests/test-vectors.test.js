import test from "node:test";
import assert from "node:assert/strict";
import { verifyTestVectors } from "../scripts/verify-test-vectors.js";

test("committed ULDA test vectors verify", async () => {
  const result = await verifyTestVectors({ print: false });

  assert.equal(result.vectorCount, 4);
  assert.ok(result.assertionCount > 0);
  assert.deepEqual(
    result.summaries.map(summary => `${summary.pack}:${summary.mode}`).sort(),
    ["compactV1:S", "compactV1:X", "simpleSig:S", "simpleSig:X"]
  );
});
