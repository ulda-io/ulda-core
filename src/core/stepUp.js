export function stepUpOriginState(parsedOrigin, options) {
  const { randomBytes } = options;
  const next = parsedOrigin.origin.slice(1);
  next.push(randomBytes(parsedOrigin.blockLen));
  return { origin: next, index: parsedOrigin.index + 1n };
}
