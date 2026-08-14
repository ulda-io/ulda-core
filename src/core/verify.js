export async function verifyWitnesses(previousWitness, candidateWitness, options) {
  const { modes, hash, hashIter, concatBytes, equalBytes, splitWitnessBlocks } = options;
  if (
    previousWitness.N !== candidateWitness.N ||
    previousWitness.mode !== candidateWitness.mode ||
    previousWitness.alg !== candidateWitness.alg
  )
    return false;
  if (candidateWitness.index <= previousWitness.index) return false;
  const ctx = { hash, hashIter, concatBytes, equalBytes, splitWitnessBlocks };
  return previousWitness.mode === "S" ?
    modes.S.verify(previousWitness, candidateWitness, ctx) :
    previousWitness.mode === "X" ?
    modes.X.verify(previousWitness, candidateWitness, ctx) :
    false;
}
