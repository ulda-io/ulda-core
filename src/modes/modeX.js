import { ULDA_ERROR_CODES, UldaError } from "../errors/index.js";

export const modeX = {
  id: "X",

  ladder: async(blocks, ctx) => {
    if (!blocks?.length)
      throw new UldaError(
        ULDA_ERROR_CODES.ULDA_MODE_EMPTY_BLOCKS,
        "_ladderX: empty blocks", {
          operation: "ladderX",
          details: { mode: "X" }
        }
      );
    const sig = [blocks[0]];
    let prev = blocks;
    for (let d = 1; d < blocks.length; d++) {
      const cur = [];
      for (let i = 0; i < prev.length - 1; i++)
        cur.push(await ctx.hash(ctx.concatBytes(prev[i], prev[i + 1]), ctx.alg));
      sig.push(cur[0]);
      prev = cur;
    }
    return { sigBlocks: sig, final: sig.at(-1) };
  },

  verify: async(previousWitness, candidateWitness, ctx) => {
    if (candidateWitness.index - previousWitness.index !== 1n) return false;
    const { N } = previousWitness;
    if (
      previousWitness.sigBytes.length !== candidateWitness.sigBytes.length ||
      previousWitness.sigBytes.length % N
    )
      return false;
    const previousBlocks = ctx.splitWitnessBlocks(previousWitness),
      candidateBlocks = ctx.splitWitnessBlocks(candidateWitness);
    for (let d = 1; d < N; d++)
      if (!ctx.equalBytes(
          await ctx.hash(
            ctx.concatBytes(previousBlocks[d - 1], candidateBlocks[d - 1]),
            previousWitness.alg
          ),
          previousBlocks[d]
        ))
        return false;
    return true;
  }
};
