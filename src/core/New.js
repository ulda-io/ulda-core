export function createOriginState(options) {
  const { N, originSize, randomBytes } = options;
  const len = originSize >>> 3;
  return {
    origin: Array.from({ length: N }, () => randomBytes(len))
  };
}
