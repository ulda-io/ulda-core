export function registerCustomHasher(options) {
  const { cfg, config, encoder, decoder } = options;
  const s = cfg.sign ?? {};
  if (typeof s.func !== "function") return undefined;

  const id = s.hash ?? "CUSTOM";
  if (!s.hash) config.sign.hash = id;
  config.externalHashers[id] = {
    fn: s.func,
    output: s.output ?? "bytes",
    size: s.originSize ?? null,
    cdn: s.cdn ?? null,
    ready: true
  };
  if (!(id in encoder.algorithm)) encoder.algorithm[id] = 0xff;
  if (encoder.algorithm[id] === 0xff) decoder.algorithm[0xff] = id;
  return { id };
}
