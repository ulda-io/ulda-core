# ULDA Pack and Version Policy

## Public API

The current public API remains:

- `New`
- `stepUp`
- `sign`
- `verify`

Pack selection must not change these method names or the directed verification
contract. New protocol behavior should be introduced through configuration,
explicit new APIs, or future versioned packs.

## Current Default

`compactV1` is the ULDA 1.0 standard/default pack.

```js
new UldaSign()
```

uses `compactV1`. Default-pack changes are version decisions and require
compatibility notes and tests.

## simpleSig

`simpleSig` is the existing v1 package format. It is now a legacy
compatibility pack. It remains supported explicitly:

```js
new UldaSign({
  sign: {
    pack: "simpleSig"
  }
})
```

The v1/simpleSig codec should continue to work independently of compactV1. Code
that expects simpleSig packages must select simpleSig explicitly when
compatibility matters. The `"v1"` pack id maps to `simpleSig` as a legacy alias.

## compactV1

`compactV1` is the ULDA 1.0 default pack. It may also be selected explicitly:

```js
new UldaSign({
  sign: {
    pack: "compactV1"
  }
})
```

It uses the compact bit-level header:

```text
[prefix 4 bits][headerSize 8 bits][inclusive 8 bits][optional fields][suffix 4 bits][body]
```

The prefix nibble is `0000`. `headerSize` is a `uint8`. The inclusive byte
contains field and mode flags. The suffix nibble is `0000`. The body starts at
byte offset `headerSize`.

Mode `S` and mode `X` are encoded in the inclusive byte. Package age maps to the
package index. In compactV1, age is canonical:

- absent age means index `0n`;
- present age is `uint32` big-endian;
- present age is always 4 bytes;
- maximum age is `4294967295`;
- age overflow is rejected.

Backup fields can be transported by the low-level header utility, but no
semantic backup behavior is defined by ULDA v1. Canonical accepted
`compactV1` packages do not set backup or reserved future-mode fields.

The low-level `compactHeader` utility can parse 8-byte ages for tooling. That
is not part of canonical `compactV1` runtime policy.

## Cross-Pack Compatibility

simpleSig and compactV1 packages are different wire formats.

The simpleSig decoder should not be expected to read compactV1 packages. The
compactV1 decoder should not be expected to read simpleSig packages.

Compatibility should be handled through explicit pack selection or a future
codec registry detection design. It should not rely on silent guessing.

## Verify Contract

Both packs use the same semantic API contract:

```js
verify(previousWitness, candidateWitness)
```

The first argument is the known older witness and the second is the candidate
newer witness. Verification is forward-only: reversed arguments and equal
indexes return `false`. The change to the existing `verify` behavior is
breaking for callers that relied on reversed arguments being accepted, but it
does not change either pack's wire format.

## Production Artifact Policy

The modular source layout is for development, testing, maintenance, review, and
auditing.

The official production artifacts are the generated single-file ESM bundles:

- `dist/ulda-core.js` for readable distribution;
- `dist/ulda-core.min.js` for size-sensitive and CDN distribution.

Both are built from the same modular source and verified by
`npm run release:check`.

## Official Profile Validation

The wire-format specification and shared test vectors are canonical fixtures
for validating official ULDA Core artifacts and permitted integrations. The
JavaScript file and module layout is an implementation detail.

These materials do not grant unrestricted permission to create or validate
ports, replacements, or other functionally equivalent offerings. Such use is
governed by [LICENSE.md](../LICENSE.md).

## Future Decisions

Future protocol and runtime decisions include:

- backup descriptor formalization;
- package kind markers for origin and witness packages;
- codec auto-detection or a richer registry.

## Non-Goals

compactV1 does not implement backup semantics yet.

compactV1 does not encrypt data.

The `UldaSign` API does not sign arbitrary messages in the traditional
digital-signature sense.

`verify` is directed from the previous witness to the candidate witness.
