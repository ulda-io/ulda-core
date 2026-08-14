import {
    base64ToBytes,
    bytesToBase64,
    bytesToHex,
    concatBytes,
    equalBytes,
    exportBytes,
    guessToBytes,
    hexToBytes,
    importBytes,
    indexToBytes
} from "./src/bytes/index.js";
import { createCodecForPack } from "./src/codecs/registry.js";
import {
    createDecoderFromEncoder,
    createDefaultEncoder,
    normalizeConfig,
    registerCustomHasher
} from "./src/config/index.js";
import { createHashProvider } from "./src/crypto/hash.js";
import { createRandomProvider } from "./src/crypto/random.js";
import { ULDA_ERROR_CODES, UldaError } from "./src/errors/index.js";
import { modeS, modeX } from "./src/modes/index.js";
import { createUldaOperations } from "./src/runtime/index.js";

class UldaSign {
    constructor(cfg = {}) {
        const g = (this.globalConfig = normalizeConfig(cfg));
        this.externalHashers = g.externalHashers;
        this.encoder = createDefaultEncoder();
        this.decoder = createDecoderFromEncoder(this.encoder);
        registerCustomHasher({ cfg, config: g, encoder: this.encoder, decoder: this.decoder });
        const codecSelection = createCodecForPack({
            pack: g.sign.pack,
            encoder: this.encoder,
            decoder: this.decoder,
            getExportFormat: () => g.fmt.export,
            getOriginSize: () => g.sign.originSize
        });
        this.codecPack = codecSelection.id;
        const codec = (this.codec = codecSelection.codec);

        const cv = (this.convert = {
            bytesToHex,
            hexToBytes,
            bytesToBase64,
            base64ToBytes,
            guessToBytes,
            indexToBytes,
            concatBytes,
            equalBytes,
            export: bytes => exportBytes(bytes, g.fmt.export),
            importToBytes: d => importBytes(d, g.fmt.export),
            splitSig: p => codec.splitWitnessBlocks(p)
        });

        const hashProvider = (this.hashProvider = createHashProvider({
            externalHashers: g.externalHashers,
            loadScriptOnce: UldaSign.loadScriptOnce,
            cryptoImpl: globalThis.crypto
        }));
        const randomProvider = (this.randomProvider = createRandomProvider({
            cryptoImpl: globalThis.crypto
        }));

        const enc = (this.enc = {
            hash: hashProvider.hash,
            hashIter: hashProvider.hashIter,
            ladder: async(blocks, mode = "S", alg = "SHA-256") =>
                mode === "X" ? enc._ladderX(blocks, alg) : enc._ladderS(blocks, alg),
            _ladderS: async(blocks, alg) =>
                modeS.ladder(blocks, { hashIter: enc.hashIter, alg }),
            _ladderX: async(blocks, alg = "SHA-256") =>
                modeX.ladder(blocks, { hash: enc.hash, concatBytes: cv.concatBytes, alg })
        });
        const operations = (this.operations = createUldaOperations({
            config: g,
            codec,
            modes: { S: modeS, X: modeX },
            hash: enc.hash,
            hashIter: enc.hashIter,
            randomBytes: len => randomProvider.randomBytes(len),
            concatBytes: cv.concatBytes,
            equalBytes: cv.equalBytes
        }));

        this.actions = {
            Sign: pkg => operations.signPackage(pkg),
            VerifyS: async(previousWitness, candidateWitness) =>
                modeS.verify(previousWitness, candidateWitness, {
                    hashIter: enc.hashIter,
                    equalBytes: cv.equalBytes,
                    splitWitnessBlocks: cv.splitSig
                }),
            VerifyX: async(previousWitness, candidateWitness) =>
                modeX.verify(previousWitness, candidateWitness, {
                    hash: enc.hash,
                    concatBytes: cv.concatBytes,
                    equalBytes: cv.equalBytes,
                    splitWitnessBlocks: cv.splitSig
                }),
            Verify: (previousWitness, candidateWitness) =>
                operations.verifyPackages(previousWitness, candidateWitness),
            import: {
                signature: pkg => codec.decodeWitness(pkg),
                origin: pkg => codec.decodeOrigin(pkg)
            },
            OriginGenerator: () => operations.originGenerator(),
            RandomBlock: len => operations.randomBlock(len),
            _hdr: (N, mode, alg, idxBytes) => {
                if (typeof codec.makeHeader === "function") {
                    return codec.makeHeader(N, mode, alg, idxBytes);
                }
                throw new UldaError(
                    ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
                    "Legacy v1 header is not available for compactV1",
                    {
                        operation: "actions._hdr",
                        details: { pack: this.codecPack }
                    }
                );
            },
            NewExporter: (originObj, index = 0n) => {
                const { N, mode, hash } = g.sign;
                return codec.encodeOrigin(originObj, index, {
                    N,
                    mode,
                    hash,
                    ageBytes: g.sign.ageBytes
                });
            },
            SignExporter: (sigBytes, index, N, mode, hash) =>
                codec.encodeWitness(sigBytes, { index, N, mode, hash, ageBytes: g.sign.ageBytes }),
            PackSignature: (sigBytes, m) =>
                codec.packWitness(sigBytes, m),
            StepUp: pkg => operations.stepUpPackage(pkg)
        };
    }

    static loadScriptOnce(src) {
        return new Promise((res, rej) => {
            if (document.querySelector(`script[src="${src}"]`)) return res();
            const s = document.createElement("script");
            s.src = src;
            s.onload = res;
            s.onerror = rej;
            document.head.appendChild(s);
        });
    }

    New(i = 0n) {
        return this.operations.newOriginPackage(i);
    }
    stepUp(pkg) {
        return this.operations.stepUpPackage(pkg);
    }
    sign(pkg) {
        return this.operations.signPackage(pkg);
    }
    verify(previousWitness, candidateWitness) {
        return this.operations.verifyPackages(previousWitness, candidateWitness);
    }
}

export default UldaSign;

