export const DEFAULT_ENCODER = Object.freeze({
  mode: Object.freeze({ S: 1, X: 2 }),
  algorithm: Object.freeze({
    "SHA-1": 1,
    "SHA-256": 2,
    "SHA-384": 3,
    "SHA-512": 4,
    "SHA3-256": 5,
    "SHA3-512": 6,
    BLAKE3: 7,
    WHIRLPOOL: 8,
    CUSTOM: 0xff
  })
});

export function createDefaultEncoder() {
  return {
    mode: { ...DEFAULT_ENCODER.mode },
    algorithm: { ...DEFAULT_ENCODER.algorithm }
  };
}

export function createDecoderFromEncoder(encoder) {
  return {
    mode: Object.fromEntries(
      Object.entries(encoder.mode).map(([name, code]) => [code, name])
    ),
    algorithm: Object.fromEntries(
      Object.entries(encoder.algorithm).map(([name, code]) => [code, name])
    )
  };
}

export function createDefaultDecoder() {
  return createDecoderFromEncoder(createDefaultEncoder());
}
