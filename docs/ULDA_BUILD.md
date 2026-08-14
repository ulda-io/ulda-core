# ULDA Build

The source tree is modular so the official protocol code remains maintainable,
testable, reviewable, and suitable for security auditing. The production
JavaScript artifact is a generated single-file bundle.

Build the bundle from source:

```bash
npm run build
```

Check the generated bundle:

```bash
npm run check:bundle
```

The build writes:

- `dist/ulda-core.js`
- `dist/ulda-core.min.js`

The readable bundle is the main artifact. The minified bundle is generated from
the same source for size-sensitive use.

`check:bundle` imports both generated bundles and verifies their default
`UldaSign` export and a complete default lifecycle. The readable bundle is also
checked for both supported pack paths. The public methods are:

- `New`
- `stepUp`
- `sign`
- `verify`

It also checks both supported pack paths:

- default `compactV1`
- explicit legacy `simpleSig` selected with `sign.pack = "simpleSig"`
- explicit `compactV1` selected with `sign.pack = "compactV1"`

The default pack is `compactV1`. `simpleSig` remains available as an explicit
legacy compatibility pack.

Distribution files should be regenerated from source and must not be edited
manually. The bundle avoids runtime multi-module loading overhead while the
source remains split into small modules for development, maintenance, review,
and auditing.
