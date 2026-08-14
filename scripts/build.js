import { mkdir, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const entryPoint = path.join(rootDir, "ulda-core.js");
const outDir = path.join(rootDir, "dist");
const bundlePath = path.join(outDir, "ulda-core.js");
const minBundlePath = path.join(outDir, "ulda-core.min.js");

const shared = {
    entryPoints: [entryPoint],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: ["es2020"],
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent"
};

async function byteSize(filePath) {
    const info = await stat(filePath);
    return info.size;
}

async function main() {
    await mkdir(outDir, { recursive: true });

    await build({
        ...shared,
        outfile: bundlePath,
        minify: false
    });

    await build({
        ...shared,
        outfile: minBundlePath,
        minify: true
    });

    const bundleBytes = await byteSize(bundlePath);
    const minBundleBytes = await byteSize(minBundlePath);

    console.log("Built ULDA bundle");
    console.log(`bundle: ${path.relative(rootDir, bundlePath)} (${bundleBytes} bytes)`);
    console.log(`minified: ${path.relative(rootDir, minBundlePath)} (${minBundleBytes} bytes)`);
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
