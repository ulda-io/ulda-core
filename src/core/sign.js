export async function signOriginState(parsedOrigin, options) {
  const { modes, hash, hashIter, concatBytes } = options;
  const mode = parsedOrigin.mode === "X" ? modes.X : modes.S;
  const { sigBlocks } = await mode.ladder(parsedOrigin.origin, {
    hash,
    hashIter,
    concatBytes,
    alg: parsedOrigin.alg
  });
  const sigBytes = concatBytes(...sigBlocks);
  return {
    sigBytes,
    sigBlocks,
    index: parsedOrigin.index,
    N: parsedOrigin.N,
    mode: parsedOrigin.mode,
    alg: parsedOrigin.alg
  };
}
