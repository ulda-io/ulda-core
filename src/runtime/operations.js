import {
  createOriginState,
  signOriginState,
  stepUpOriginState,
  verifyWitnesses
} from "../core/index.js";

export function createUldaOperations(options) {
  const {
    config,
    codec,
    modes,
    hash,
    hashIter,
    randomBytes,
    concatBytes,
    equalBytes
  } = options;

  const randomBlock = len => randomBytes(len);

  const originGenerator = () =>
    createOriginState({
      N: config.sign.N,
      originSize: config.sign.originSize,
      randomBytes: randomBlock
    });

  const newOriginPackage = (index = 0n) =>
    codec.encodeOrigin(originGenerator(), index, {
      N: config.sign.N,
      mode: config.sign.mode,
      hash: config.sign.hash,
      ageBytes: config.sign.ageBytes
    });

  const stepUpPackage = pkg => {
    const parsedOrigin = codec.decodeOrigin(pkg),
      next = stepUpOriginState(parsedOrigin, { randomBytes: randomBlock });
    return codec.encodeOrigin({ origin: next.origin }, next.index, {
      N: config.sign.N,
      mode: config.sign.mode,
      hash: config.sign.hash,
      ageBytes: config.sign.ageBytes
    });
  };

  const signPackage = async pkg => {
    const parsedOrigin = codec.decodeOrigin(pkg),
      result = await signOriginState(parsedOrigin, {
        modes,
        hash,
        hashIter,
        concatBytes
      });
    return codec.packWitness(result.sigBytes, {
      index: result.index,
      N: result.N,
      mode: result.mode,
      alg: result.alg,
      ageBytes: config.sign.ageBytes
    });
  };

  const verifyPackages = async(previousPackage, candidatePackage) => {
    const previousWitness = codec.decodeWitness(previousPackage),
      candidateWitness = codec.decodeWitness(candidatePackage);
    return verifyWitnesses(previousWitness, candidateWitness, {
      modes,
      hash,
      hashIter,
      concatBytes,
      equalBytes,
      splitWitnessBlocks: codec.splitWitnessBlocks
    });
  };

  return {
    randomBlock,
    originGenerator,
    newOriginPackage,
    stepUpPackage,
    signPackage,
    verifyPackages
  };
}
