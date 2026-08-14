import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import UldaSign from "../ulda-sign.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const vectorsPath = resolve(repoRoot, "test-vectors", "ulda-v1-vectors.json");

function readVectors() {
  return JSON.parse(readFileSync(vectorsPath, "utf8"));
}

function configFor(vector) {
  return {
    fmt: { export: vector.exportFormat },
    sign: {
      pack: vector.pack,
      mode: vector.mode,
      N: vector.N,
      hash: vector.hash,
      originSize: vector.originSize
    }
  };
}

function byteLength(ulda, pkg) {
  return ulda.convert.importToBytes(pkg).length;
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

async function verifyVector(vector) {
  const ulda = new UldaSign(configFor(vector));
  let assertions = 0;

  for (const [age, entry] of Object.entries(vector.ages)) {
    const witness = await ulda.sign(entry.origin);
    assertEqual(witness, entry.witness, `${vector.id} age ${age} witness`);
    assertions++;

    const origin = ulda.codec.decodeOrigin(entry.origin);
    const decodedWitness = ulda.codec.decodeWitness(entry.witness);
    const originHeaderSize = origin.header?.headerSize ?? origin.bytes[1];
    const witnessHeaderSize = decodedWitness.header?.headerSize ?? decodedWitness.bytes[1];
    const originBodyLength = origin.body?.length ?? byteLength(ulda, entry.origin) - originHeaderSize;
    const witnessBodyLength =
      decodedWitness.body?.length ?? byteLength(ulda, entry.witness) - witnessHeaderSize;

    assertEqual(byteLength(ulda, entry.origin), entry.originByteLength, `${vector.id} age ${age} originByteLength`);
    assertEqual(byteLength(ulda, entry.witness), entry.witnessByteLength, `${vector.id} age ${age} witnessByteLength`);
    assertEqual(origin.index.toString(), entry.decodedOriginIndex, `${vector.id} age ${age} decodedOriginIndex`);
    assertEqual(decodedWitness.index.toString(), entry.decodedWitnessIndex, `${vector.id} age ${age} decodedWitnessIndex`);
    assertEqual(origin.mode, entry.decodedMode, `${vector.id} age ${age} decodedMode`);
    assertEqual(origin.alg, entry.decodedAlg, `${vector.id} age ${age} decodedAlg`);
    assertEqual(origin.N, entry.decodedN, `${vector.id} age ${age} decodedN`);
    assertEqual(originHeaderSize, entry.originHeaderSize, `${vector.id} age ${age} originHeaderSize`);
    assertEqual(witnessHeaderSize, entry.witnessHeaderSize, `${vector.id} age ${age} witnessHeaderSize`);
    assertEqual(originBodyLength, entry.originBodyLength, `${vector.id} age ${age} originBodyLength`);
    assertEqual(witnessBodyLength, entry.witnessBodyLength, `${vector.id} age ${age} witnessBodyLength`);
    assertions += 11;
  }

  for (const check of vector.verify) {
    const actual = await ulda.verify(
      vector.ages[String(check.from)].witness,
      vector.ages[String(check.to)].witness
    );
    assertEqual(actual, check.expected, `${vector.id} verify ${check.from}->${check.to}`);
    assertions++;
  }

  return assertions;
}

export async function verifyTestVectors(options = {}) {
  const document = readVectors();
  let totalAssertions = 0;
  const summaries = [];

  if (document.schema !== "ulda-test-vectors") {
    throw new Error(`Unexpected vector schema: ${document.schema}`);
  }

  for (const vector of document.vectors) {
    const assertions = await verifyVector(vector);
    totalAssertions += assertions;
    summaries.push({
      id: vector.id,
      pack: vector.pack,
      mode: vector.mode,
      assertions
    });
    if (options.print !== false) {
      console.log(`${vector.id}: pack=${vector.pack}, mode=${vector.mode}, assertions=${assertions}`);
    }
  }

  if (options.print !== false) {
    console.log(`Verified ${document.vectors.length} vector sets, ${totalAssertions} assertions`);
  }

  return {
    vectorCount: document.vectors.length,
    assertionCount: totalAssertions,
    summaries
  };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyTestVectors().catch(err => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
