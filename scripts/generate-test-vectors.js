import { webcrypto } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import UldaSign from "../ulda-sign.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const vectorsDir = resolve(repoRoot, "test-vectors");
const vectorsPath = resolve(vectorsDir, "ulda-v1-vectors.json");

const DEFAULTS = Object.freeze({
  N: 5,
  originSize: 256,
  blockLen: 32,
  hash: "SHA-256",
  exportFormat: "hex"
});
const AGES = [0, 1, 2, 4, 5];
const PACKS = ["simpleSig", "compactV1"];
const MODES = ["S", "X"];

function block(blockNumber) {
  return Uint8Array.from(
    { length: DEFAULTS.blockLen },
    (_, j) => (blockNumber * DEFAULTS.blockLen + j) & 0xff
  );
}

function originAt(age) {
  return Array.from({ length: DEFAULTS.N }, (_, i) => block(age + i));
}

function configFor(pack, mode) {
  return {
    fmt: { export: DEFAULTS.exportFormat },
    sign: {
      pack,
      mode,
      N: DEFAULTS.N,
      hash: DEFAULTS.hash,
      originSize: DEFAULTS.originSize
    }
  };
}

function packageBytes(ulda, pkg) {
  return ulda.convert.importToBytes(pkg);
}

function packageMetadata(ulda, kind, pkg) {
  const bytes = packageBytes(ulda, pkg);
  const decoded = kind === "origin" ?
    ulda.codec.decodeOrigin(pkg) :
    ulda.codec.decodeWitness(pkg);
  const headerSize = decoded.header?.headerSize ?? decoded.bytes?.[1] ?? bytes[1];
  const bodyLength = decoded.body?.length ?? bytes.length - headerSize;

  return {
    byteLength: bytes.length,
    decodedIndex: decoded.index.toString(),
    decodedMode: decoded.mode,
    decodedAlg: decoded.alg,
    decodedN: decoded.N,
    headerSize,
    bodyLength
  };
}

function verifyMatrix(mode) {
  if (mode === "S") {
    return [
      { from: 0, to: 1, expected: true },
      { from: 1, to: 0, expected: false },
      { from: 0, to: 4, expected: true },
      { from: 0, to: 5, expected: false },
      { from: 0, to: 0, expected: false }
    ];
  }

  return [
    { from: 0, to: 1, expected: true },
    { from: 1, to: 0, expected: false },
    { from: 0, to: 2, expected: false },
    { from: 0, to: 0, expected: false }
  ];
}

async function buildVector(pack, mode) {
  const ulda = new UldaSign(configFor(pack, mode));
  const ages = {};

  for (const age of AGES) {
    const origin = ulda.codec.encodeOrigin(
      { origin: originAt(age) },
      BigInt(age),
      {
        N: DEFAULTS.N,
        mode,
        hash: DEFAULTS.hash
      }
    );
    const witness = await ulda.sign(origin);
    const originMeta = packageMetadata(ulda, "origin", origin);
    const witnessMeta = packageMetadata(ulda, "witness", witness);

    ages[String(age)] = {
      origin,
      witness,
      originByteLength: originMeta.byteLength,
      witnessByteLength: witnessMeta.byteLength,
      decodedOriginIndex: originMeta.decodedIndex,
      decodedWitnessIndex: witnessMeta.decodedIndex,
      decodedMode: originMeta.decodedMode,
      decodedAlg: originMeta.decodedAlg,
      decodedN: originMeta.decodedN,
      originHeaderSize: originMeta.headerSize,
      witnessHeaderSize: witnessMeta.headerSize,
      originBodyLength: originMeta.bodyLength,
      witnessBodyLength: witnessMeta.bodyLength
    };
  }

  const verify = verifyMatrix(mode);
  for (const check of verify) {
    const actual = await ulda.verify(
      ages[String(check.from)].witness,
      ages[String(check.to)].witness
    );
    if (actual !== check.expected) {
      throw new Error(
        `${pack}/${mode} verify ${check.from}->${check.to}: expected ${check.expected}, got ${actual}`
      );
    }
  }

  return {
    id: `${pack}-${mode}-N5-SHA256`,
    pack,
    mode,
    N: DEFAULTS.N,
    hash: DEFAULTS.hash,
    originSize: DEFAULTS.originSize,
    exportFormat: DEFAULTS.exportFormat,
    ages,
    verify
  };
}

async function main() {
  const vectors = [];
  for (const pack of PACKS) {
    for (const mode of MODES) {
      vectors.push(await buildVector(pack, mode));
    }
  }

  const document = {
    schema: "ulda-test-vectors",
    schemaVersion: 1,
    generatedBy: "scripts/generate-test-vectors.js",
    notes: [
      "Synthetic deterministic blocks only.",
      "Origin packages contain synthetic private test blocks and must not be used as real secrets.",
      "Vector files do not include timestamps so diffs remain stable."
    ],
    defaults: DEFAULTS,
    blockRule: "byte[j] = (blockNumber * 32 + j) & 0xff",
    vectors
  };

  mkdirSync(vectorsDir, { recursive: true });
  writeFileSync(vectorsPath, `${JSON.stringify(document, null, 2)}\n`);
  console.log(`Generated ${vectors.length} ULDA vector sets at test-vectors/ulda-v1-vectors.json`);
}

main().catch(err => {
  console.error(err.message);
  process.exitCode = 1;
});
