import { createCompactV1Codec } from "./compactV1.js";
import { createV1Codec } from "./v1.js";
import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export const ULDA_CODEC_PACKS = Object.freeze({
  SIMPLE_SIG: "simpleSig",
  V1: "v1",
  COMPACT_V1: "compactV1"
});

export function normalizeCodecPack(pack) {
  if (pack === undefined || pack === null) return ULDA_CODEC_PACKS.COMPACT_V1;
  if (pack === ULDA_CODEC_PACKS.SIMPLE_SIG) return ULDA_CODEC_PACKS.SIMPLE_SIG;
  if (pack === ULDA_CODEC_PACKS.V1) return ULDA_CODEC_PACKS.SIMPLE_SIG;
  if (pack === ULDA_CODEC_PACKS.COMPACT_V1 || pack === "compact") {
    return ULDA_CODEC_PACKS.COMPACT_V1;
  }

  throw new UldaError(
    ULDA_ERROR_CODES.ULDA_CONFIG_INVALID,
    "unknown codec pack",
    {
      operation: "normalizeCodecPack",
      details: { pack }
    }
  );
}

export function createCodecForPack(options = {}) {
  const {
    pack,
    encoder,
    decoder,
    getExportFormat,
    getOriginSize
  } = options;
  const id = normalizeCodecPack(pack);

  if (id === ULDA_CODEC_PACKS.COMPACT_V1) {
    return {
      id,
      codec: createCompactV1Codec({
        encoder,
        decoder,
        getExportFormat,
        getOriginSize
      })
    };
  }

  return {
    id: ULDA_CODEC_PACKS.SIMPLE_SIG,
    codec: createV1Codec({
      encoder,
      decoder,
      getExportFormat,
      getOriginSize
    })
  };
}
