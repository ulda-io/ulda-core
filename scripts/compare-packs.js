import { webcrypto } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import UldaSign from "../ulda-sign.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const docPath = resolve(repoRoot, "docs", "ULDA_PACK_COMPARISON.md");
const START_MARKER = "<!-- comparison-output:start -->";
const END_MARKER = "<!-- comparison-output:end -->";

function parseIterations(argv) {
  const index = argv.indexOf("--iterations");
  if (index === -1) return 100;
  const value = Number(argv[index + 1]);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error("--iterations must be a positive integer");
  }
  return value;
}

function baseConfig(pack, exportFormat) {
  const cfg = {
    fmt: { export: exportFormat },
    sign: {
      mode: "S",
      N: 5,
      hash: "SHA-256",
      originSize: 256
    }
  };
  if (pack !== undefined) cfg.sign.pack = pack;
  return cfg;
}

function buildConfigs() {
  const formats = ["hex", "base64", "bytes"];
  return formats.flatMap(exportFormat => [
    {
      label: `compactV1 default uint32-age ${exportFormat}`,
      pack: "compactV1",
      ageBytes: 4,
      exportFormat,
      cfg: baseConfig(undefined, exportFormat)
    },
    {
      label: `simpleSig legacy ${exportFormat}`,
      pack: "simpleSig",
      ageBytes: "",
      exportFormat,
      cfg: baseConfig("simpleSig", exportFormat)
    }
  ]);
}

function encodedLength(pkg) {
  return pkg instanceof Uint8Array ? pkg.length : String(pkg).length;
}

function importedBytes(ulda, pkg) {
  return ulda.convert.importToBytes(pkg);
}

function packageInfo(ulda, kind, pkg) {
  const bytes = importedBytes(ulda, pkg);
  const decoded = kind === "origin" ?
    ulda.codec.decodeOrigin(pkg) :
    ulda.codec.decodeWitness(pkg);
  const headerSize = decoded.header?.headerSize ?? decoded.bytes?.[1] ?? bytes[1] ?? "";
  const bodyLength = decoded.body?.length ?? (headerSize === "" ? "" : bytes.length - headerSize);

  return {
    encodedLength: encodedLength(pkg),
    byteLength: bytes.length,
    headerSize,
    bodyLength
  };
}

function formatMs(value) {
  return value.toFixed(3);
}

function formatNumber(value) {
  return Number.isFinite(value) ? value.toFixed(2) : "0.00";
}

async function capturePackages(entry) {
  const constructorStart = performance.now();
  const ulda = new UldaSign(entry.cfg);
  const constructorMs = performance.now() - constructorStart;

  const newStart = performance.now();
  const origin0 = ulda.New(0n);
  const newMs = performance.now() - newStart;

  const initialSignStart = performance.now();
  const sig0 = await ulda.sign(origin0);
  const initialSignMs = performance.now() - initialSignStart;

  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);
  const forwardOk = await ulda.verify(sig0, sig1);
  const reverseOk = await ulda.verify(sig1, sig0);

  if (forwardOk !== true || reverseOk !== false) {
    throw new Error(`${entry.label}: expected forward verify true and reverse verify false`);
  }

  return {
    ulda,
    constructorMs,
    newMs,
    initialSignMs,
    packages: {
      origin0: packageInfo(ulda, "origin", origin0),
      sig0: packageInfo(ulda, "witness", sig0),
      origin1: packageInfo(ulda, "origin", origin1),
      sig1: packageInfo(ulda, "witness", sig1)
    }
  };
}

async function warmUp(entry) {
  const ulda = new UldaSign(entry.cfg);
  let origin = ulda.New(0n);
  let sig = await ulda.sign(origin);

  for (let i = 0; i < 5; i++) {
    const nextOrigin = ulda.stepUp(origin);
    const nextSig = await ulda.sign(nextOrigin);
    if ((await ulda.verify(sig, nextSig)) !== true) {
      throw new Error(`${entry.label}: warm-up verification failed`);
    }
    origin = nextOrigin;
    sig = nextSig;
  }
}

async function benchmark(entry, iterations) {
  await warmUp(entry);

  const packageCapture = await capturePackages(entry);
  const ulda = packageCapture.ulda;
  let origin = ulda.New(0n);
  let sig = await ulda.sign(origin);
  let stepUpMs = 0;
  let signMs = 0;
  let verifyMs = 0;

  const totalStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    const stepStart = performance.now();
    const nextOrigin = ulda.stepUp(origin);
    stepUpMs += performance.now() - stepStart;

    const signStart = performance.now();
    const nextSig = await ulda.sign(nextOrigin);
    signMs += performance.now() - signStart;

    const verifyStart = performance.now();
    const ok = await ulda.verify(sig, nextSig);
    verifyMs += performance.now() - verifyStart;

    if (ok !== true) {
      throw new Error(`${entry.label}: verification failed at cycle ${i}`);
    }

    origin = nextOrigin;
    sig = nextSig;
  }
  const totalLoopMs = performance.now() - totalStart;

  return {
    label: entry.label,
    pack: packageCapture.ulda.codecPack,
    mode: entry.cfg.sign.mode,
    N: entry.cfg.sign.N,
    ageBytes: entry.ageBytes,
    exportFormat: entry.exportFormat,
    iterations,
    constructorMs: packageCapture.constructorMs,
    newMs: packageCapture.newMs,
    initialSignMs: packageCapture.initialSignMs,
    stepUpMs,
    signMs,
    verifyMs,
    totalLoopMs,
    msPerCycle: totalLoopMs / iterations,
    cyclesPerSecond: iterations / (totalLoopMs / 1000),
    packages: packageCapture.packages
  };
}

function makeSizeRows(results) {
  return results.flatMap(result =>
    Object.entries(result.packages).map(([packageName, info]) => ({
      label: result.label,
      pack: result.pack,
      exportFormat: result.exportFormat,
      ageBytes: result.ageBytes,
      packageName,
      ...info
    }))
  );
}

function markdownTable(headers, rows) {
  const line = values => `| ${values.join(" | ")} |`;
  return [
    line(headers),
    line(headers.map(() => "---")),
    ...rows.map(row => line(headers.map(header => String(row[header] ?? ""))))
  ].join("\n");
}

function renderConsole(results) {
  console.log(`ULDA pack comparison (${results[0]?.iterations ?? 0} iterations)`);
  console.log("");
  for (const result of results) {
    console.log(
      `${result.label}: ${formatMs(result.msPerCycle)} ms/cycle, ` +
      `${formatNumber(result.cyclesPerSecond)} cycles/sec`
    );
    for (const [name, info] of Object.entries(result.packages)) {
      console.log(
        `  ${name}: encoded=${info.encodedLength}, bytes=${info.byteLength}, ` +
        `header=${info.headerSize}, body=${info.bodyLength}`
      );
    }
  }
}

function renderMarkdown(results) {
  const speedRows = results.map(result => ({
    Config: result.label,
    Pack: result.pack,
    Format: result.exportFormat,
    AgeBytes: result.ageBytes,
    Iterations: result.iterations,
    ConstructorMs: formatMs(result.constructorMs),
    NewMs: formatMs(result.newMs),
    InitialSignMs: formatMs(result.initialSignMs),
    StepUpMs: formatMs(result.stepUpMs),
    SignMs: formatMs(result.signMs),
    VerifyMs: formatMs(result.verifyMs),
    TotalLoopMs: formatMs(result.totalLoopMs),
    MsPerCycle: formatMs(result.msPerCycle),
    CyclesPerSecond: formatNumber(result.cyclesPerSecond)
  }));
  const sizeRows = makeSizeRows(results).map(row => ({
    Config: row.label,
    Pack: row.pack,
    Format: row.exportFormat,
    AgeBytes: row.ageBytes,
    Package: row.packageName,
    EncodedLength: row.encodedLength,
    ByteLength: row.byteLength,
    HeaderSize: row.headerSize,
    BodyLength: row.bodyLength
  }));

  return [
    START_MARKER,
    "",
    `Generated by \`npm run compare:packs -- --iterations ${results[0]?.iterations ?? 0}\`.`,
    "",
    "### Speed Results",
    "",
    markdownTable(
      [
        "Config",
        "Pack",
        "Format",
        "AgeBytes",
        "Iterations",
        "ConstructorMs",
        "NewMs",
        "InitialSignMs",
        "StepUpMs",
        "SignMs",
        "VerifyMs",
        "TotalLoopMs",
        "MsPerCycle",
        "CyclesPerSecond"
      ],
      speedRows
    ),
    "",
    "### Package Size Results",
    "",
    markdownTable(
      [
        "Config",
        "Pack",
        "Format",
        "AgeBytes",
        "Package",
        "EncodedLength",
        "ByteLength",
        "HeaderSize",
        "BodyLength"
      ],
      sizeRows
    ),
    "",
    END_MARKER
  ].join("\n");
}

function updateDoc(results) {
  const current = readFileSync(docPath, "utf8");
  const rendered = renderMarkdown(results);
  const start = current.indexOf(START_MARKER);
  const end = current.indexOf(END_MARKER);

  if (start === -1 || end === -1 || end < start) {
    writeFileSync(docPath, `${current.trimEnd()}\n\n${rendered}\n`);
    return;
  }

  const before = current.slice(0, start);
  const after = current.slice(end + END_MARKER.length);
  writeFileSync(docPath, `${before}${rendered}${after}`);
}

async function main() {
  const iterations = parseIterations(process.argv.slice(2));
  const results = [];
  for (const entry of buildConfigs()) {
    results.push(await benchmark(entry, iterations));
  }

  renderConsole(results);
  updateDoc(results);
  console.log("");
  console.log("Updated docs/ULDA_PACK_COMPARISON.md");
}

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
