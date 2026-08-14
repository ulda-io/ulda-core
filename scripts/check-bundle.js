import assert from "node:assert/strict";
import { stat } from "node:fs/promises";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundlePath = path.join(rootDir, "dist", "ulda-core.js");
const minBundlePath = path.join(rootDir, "dist", "ulda-core.min.js");

async function checkPack(UldaSign, label, config) {
    const ulda = new UldaSign(config);
    const origin0 = ulda.New();
    const sig0 = await ulda.sign(origin0);
    const origin1 = ulda.stepUp(origin0);
    const sig1 = await ulda.sign(origin1);

    assert.equal(typeof ulda.New, "function");
    assert.equal(typeof ulda.stepUp, "function");
    assert.equal(typeof ulda.sign, "function");
    assert.equal(typeof ulda.verify, "function");
    assert.equal(await ulda.verify(sig0, sig1), true, `${label} directed forward verify failed`);
    assert.equal(
        await ulda.verify(sig1, sig0),
        false,
        `${label} reversed-order verify must return false`
    );

    return label;
}

async function optionalSize(filePath) {
    try {
        const info = await stat(filePath);
        return info.size;
    } catch {
        return null;
    }
}

async function main() {
    const readableModule = await import(pathToFileURL(bundlePath).href);
    const UldaSign = readableModule.default;
    assert.equal(typeof UldaSign, "function", "Readable bundle default export must be UldaSign");

    await checkPack(UldaSign, "default compactV1", undefined);
    await checkPack(UldaSign, "explicit simpleSig", { sign: { pack: "simpleSig" } });
    await checkPack(UldaSign, "explicit compactV1", { sign: { pack: "compactV1" } });

    const bundleBytes = await optionalSize(bundlePath);
    const minBundleBytes = await optionalSize(minBundlePath);
    assert.notEqual(minBundleBytes, null, "Minified bundle must exist");

    const minifiedModule = await import(pathToFileURL(minBundlePath).href);
    const MinifiedUldaSign = minifiedModule.default;
    assert.equal(
        typeof MinifiedUldaSign,
        "function",
        "Minified bundle default export must be UldaSign"
    );
    await checkPack(MinifiedUldaSign, "minified default compactV1", undefined);

    console.log(`bundle: ${path.relative(rootDir, bundlePath)} (${bundleBytes} bytes)`);
    console.log(`minified: ${path.relative(rootDir, minBundlePath)} (${minBundleBytes} bytes)`);
    console.log("default compactV1 ok");
    console.log("explicit simpleSig ok");
    console.log("explicit compactV1 ok");
    console.log("minified default compactV1 ok");
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
