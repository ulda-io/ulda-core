export const modeS = {
  id: "S",

  ladder: async(blocks, ctx) => {
    const sig = [];
    for (let i = 0; i < blocks.length; i++)
      sig.push(await ctx.hashIter(blocks[i], i, ctx.alg));
    return { sigBlocks: sig, final: sig.at(-1) };
  },

  verify: async(previousWitness, candidateWitness, ctx) => {
    const gap = candidateWitness.index - previousWitness.index;
    if (gap <= 0n || gap >= BigInt(previousWitness.N)) return false;
    const iterations = Number(gap);
    if (
      previousWitness.originLen !== candidateWitness.originLen ||
      previousWitness.blkLen !== candidateWitness.blkLen
    )
      return false;
    const previousBlocks = ctx.splitWitnessBlocks(previousWitness),
      candidateBlocks = ctx.splitWitnessBlocks(candidateWitness);
    for (let i = 0; i < previousWitness.N - iterations; i++)
      if (!ctx.equalBytes(
          await ctx.hashIter(candidateBlocks[i], iterations, previousWitness.alg),
          previousBlocks[i + iterations]
        ))
        return false;
    return true;
  }
};
