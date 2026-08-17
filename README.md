# ULDA Core

ULDA Core is the official low-level JavaScript implementation of the ULDA v1
state-lineage protocol. It creates private rolling origins, derives public
witnesses from them, and checks whether a candidate has the required
hash-linked overlap with a previously accepted witness at a permitted future
position.

The npm package name is `ulda-core`. Its default export is the `UldaSign`
protocol class. A future high-level ULDA library and the ULDA server/container
are separate products and are not covered by this package, its API, security
policy, or license.

This repository contains the protocol core itself: codecs, cryptographic
operations, modes, runtime orchestration, deterministic test vectors, and
single-file distribution bundles.

The protocol and wire-format rules are defined in the
[ULDA Manifest](MANIFEST.md). Deployment requirements, known limitations, and
vulnerability reporting are defined in the [Security Policy](SECURITY.md).

## Scope

The core provides:

- private origin generation with cryptographically secure randomness;
- one-step origin advancement through a rolling window;
- witness generation;
- directed old-to-new witness verification;
- skippable mode S and adjacent-only mode X;
- the default `compactV1` package codec;
- the `simpleSig` compatibility codec;
- hex, Base64, and `Uint8Array` package representations;
- built-in Web Crypto SHA-1 and SHA-2 hashing;
- registration of external hash implementations;
- deterministic official release vectors;
- modular source code and generated single-file ESM bundles.

ULDA Core does not encrypt data, manage keys, establish the identity of a
stream, coordinate competing writers, or sign arbitrary application payloads.
Those concerns belong to the protocol or application built around the core.

## Runtime requirements

ULDA Core supports Node.js 22 or later and modern browsers that provide the Web
Crypto API:

- `crypto.getRandomValues` for private origin generation;
- `crypto.subtle.digest` for built-in hash algorithms.

The package is ESM-only and does not provide CommonJS or TypeScript declaration
artifacts.

## Installation

Install ULDA Core from npm:

```bash
npm install ulda-core
```

Import the default `UldaSign` class:

```js
import UldaSign from "ulda-core";
```

The package root resolves to the readable ESM bundle in `dist/ulda-core.js`.
Files in `src/` are included for review, maintenance, and auditing, but they
are not supported public import paths.

For a version-pinned browser ESM import:

```js
import UldaSign from "https://cdn.jsdelivr.net/npm/ulda-core@1.0.1/dist/ulda-core.min.js";
```

## Development from source

```bash
git clone https://github.com/ulda-io/ulda-core.git
cd ulda-core
npm ci
npm run release:check
```

Import the canonical source entry from within the repository:

```js
import UldaSign from "./ulda-core.js";
```

## Quick start

```js
import UldaSign from "ulda-core";

const ulda = new UldaSign();

// An origin is private state and must not be published or logged.
let origin = ulda.New();

// A witness is the public representation of the current state.
const witness0 = await ulda.sign(origin);

// Advance the private state and create its next public witness.
origin = ulda.stepUp(origin);
const witness1 = await ulda.sign(origin);

// Verification is directed: accepted older state first, candidate second.
const valid = await ulda.verify(witness0, witness1);

console.log(valid); // true
```

`stepUp` returns a new encoded origin package and does not mutate the supplied
package. The caller must persist the returned origin if the chain is expected
to continue from it.

## Core lifecycle

```text
New() -> private origin k -> sign() -> public witness k
              |
           stepUp()
              v
         private origin k+1 -> sign() -> public witness k+1

verify(public witness k, public witness k+1)
```

`verify` is stateless: the caller supplies both witnesses. An integrating
verifier must persist its last accepted witness, check the candidate in the
forward direction, and replace stored state atomically only after successful
verification.

Calling `stepUp` several times on the same old origin creates competing
branches. Selecting one branch and coordinating multiple writers are outside
the core.

## Public API

The supported public API for the `1.0.x` release line consists of four methods.

The instance also exposes compatibility facades and internal composition
objects from the current implementation. They are unsupported implementation
details, are not part of the stable 1.0 API, and may change in minor releases.
Applications should depend only on the four methods below.

### `New(index = 0n)`

Creates a fresh private origin package at the supplied unsigned index.

This method is synchronous. With the default configuration it returns a
lowercase hexadecimal string.

The index is metadata only. Creating a new origin with a nonzero index does not
connect it to an existing chain.

### `stepUp(originPackage)`

Decodes an origin, removes its oldest private block, appends a fresh random
block, increments the index by one, and returns the newly encoded origin.

This method is synchronous and does not mutate its input.

### `sign(originPackage)`

Derives a public witness from an encoded private origin.

This method is asynchronous because witness construction uses cryptographic
hash operations. It returns the witness in the configured export format.

The method name refers to ULDA witness generation. It does not accept or sign
an arbitrary message.

### `verify(previousWitness, candidateWitness)`

Checks whether `candidateWitness` has the required hash-linked overlap with
`previousWitness` at an allowed future position:

```js
const valid = await ulda.verify(previousWitness, candidateWitness);
```

This method is asynchronous and returns a boolean for a well-formed transition.
It returns `false` when:

- the candidate index is equal to or lower than the previous index;
- the forward gap is not permitted by the selected mode;
- height, mode, or hash metadata differs;
- an authenticated overlap commitment does not match.

Malformed packages and unavailable hash implementations can throw an
`UldaError`.

The argument order is part of the contract. Reversing otherwise valid
witnesses returns `false`.

## Verification modes

| Mode | Accepted forward gap | Behavior |
| --- | --- | --- |
| `S` | `1 <= gap < N` | Allows a bounded skip over missing intermediate witnesses |
| `X` | `gap = 1` | Requires every adjacent transition |

Mode S is the default.

With `N = 5`, mode S accepts transitions with gaps from one through four and
rejects a gap of five or greater. Mode X accepts only the next index.

In the `1.0.x` release line, non-default Mode X profiles require separate
review. The JavaScript implementation expects compatible total witness lengths
and may reject a Mode X profile when its origin-block length differs from the
digest length.

Both constructions verify overlapping commitments. The newly introduced tail
of a candidate is not authenticated by its predecessor; later transitions
constrain it. This behavior is part of the current v1 protocol and is described
in detail in the [manifest security section](MANIFEST.md#8-security-considerations).

## Configuration

```js
const ulda = new UldaSign({
  fmt: {
    export: "hex"
  },
  sign: {
    N: 5,
    mode: "S",
    hash: "SHA-256",
    originSize: 256,
    pack: "compactV1",
    ageBytes: 4
  }
});
```

### Defaults

| Option | Default | Supported values or meaning |
| --- | --- | --- |
| `fmt.export` | `"hex"` | `"hex"`, `"base64"`, or `"bytes"` |
| `sign.N` | `5` | Rolling-window height |
| `sign.mode` | `"S"` | `"S"` or `"X"` |
| `sign.hash` | `"SHA-256"` | Hash identifier encoded in the package |
| `sign.originSize` | `256` | Size of each private origin block in bits |
| `sign.pack` | `"compactV1"` | `"compactV1"` or `"simpleSig"` |
| `sign.ageBytes` | `4` | Canonical uint32 age for the current runtime |

A valid profile uses `2 <= N <= 255` and a positive, byte-aligned
`originSize`. The current configuration layer does not validate every protocol
policy constraint, so callers must use reviewed and consistent parameter sets.

Producers and verifiers for one stream must agree on the pack, mode, height,
hash implementation, and origin block size.

## Hash algorithms

The core delegates these algorithms directly to Web Crypto:

- `SHA-1`;
- `SHA-256`;
- `SHA-384`;
- `SHA-512`.

SHA-1 is retained for format compatibility and should not be selected for new
security designs.

Wire identifiers also exist for SHA3-256, SHA3-512, BLAKE3, and WHIRLPOOL, but
their implementations are not bundled with the core. They require an external
hasher.

### Registering an external hasher

An implementation for a known wire identifier can be supplied through
`externalHashers`:

```js
const ulda = new UldaSign({
  sign: {
    hash: "BLAKE3",
    originSize: 256
  },
  externalHashers: {
    BLAKE3: {
      fn: async bytes => blake3(bytes),
      output: "bytes",
      size: 256,
      ready: true
    }
  }
});
```

An arbitrary custom identifier can instead be registered through `sign.func`:

```js
const ulda = new UldaSign({
  sign: {
    hash: "MY-HASH-256",
    originSize: 256,
    func: async bytes => myHash(bytes),
    output: "bytes"
  }
});
```

Every participant must use the same custom implementation and output
parameters. The custom algorithm code does not identify an arbitrary function
without that out-of-band agreement.

## Package formats

### `compactV1`

`compactV1` is the default format. Its compact header carries or implies:

- window height `N`;
- mode S or X;
- hash algorithm identifier;
- unsigned state age;
- reserved flag positions for future backup-related fields, which canonical
  ULDA v1 packages must leave unused.

Age `0` is represented by an omitted field. A nonzero age is encoded as a
four-byte unsigned big-endian integer. The maximum supported age is
`4294967295`.

The format does not encode package kind, origin block size, stream identity, or
payload identity.

### `simpleSig`

`simpleSig` is a compatibility format included in the current core. It must be
selected explicitly:

```js
const ulda = new UldaSign({
  sign: {
    pack: "simpleSig"
  }
});
```

The `"v1"` pack identifier is an alias for `simpleSig`.

`compactV1` and `simpleSig` use different headers. The core does not
auto-detect them, and a runtime configured for one pack must not be expected to
decode the other.

## Single-file bundles

The maintained implementation is modular, while the production artifacts are
generated as single-file ES modules:

- `dist/ulda-core.js` — readable bundle;
- `dist/ulda-core.min.js` — minified bundle.

Both bundles are generated from the same source and expose the same API and
behavior. The minified file differs only in representation and size.

Build them with:

```bash
npm run build
```

Import a bundle locally or from a static host:

```js
import UldaSign from "./dist/ulda-core.min.js";
```

The bundles export the same default `UldaSign` class as `ulda-core.js`. They do
not create a global browser variable. Use them from `<script type="module">` or
another ESM loader.

Bundling keeps development code split into reviewable modules while avoiding
runtime loading of the complete source module graph. Files in `dist/` are
generated artifacts and must not be edited manually.

## Development and verification

Run the complete test suite:

```bash
npm test
```

Build and verify the distribution bundles:

```bash
npm run build
npm run check:bundle
```

Verify the committed official release vectors:

```bash
npm run verify:vectors
```

Regenerate vectors only when an intentional protocol change requires it:

```bash
npm run generate:vectors
```

Compare supported package formats locally:

```bash
npm run compare:packs
```

Generated vector changes must be reviewed as wire-format or protocol changes,
not accepted as routine snapshot updates.

## Repository layout

```text
ulda-core.js       Canonical package source entry
ulda-sign.js       UldaSign protocol class composition
src/bytes/         Byte conversion and comparison utilities
src/codecs/        compactV1, simpleSig, and compact-header codecs
src/config/        Defaults, normalization, and custom hasher registration
src/core/          Origin, step-up, witness, and verification operations
src/crypto/        Hash and secure-random providers
src/errors/        Structured error type and error codes
src/modes/         Mode S and mode X constructions
src/runtime/       Encoded package orchestration
dist/              Generated single-file ESM bundles
test-vectors/      Deterministic official release fixtures
tests/             Automated behavior and compatibility tests
scripts/           Build, bundle, vector, and comparison tooling
docs/              Detailed implementation documentation
```

The module layout is an implementation detail. The Manifest, wire format,
documentation, and deterministic vectors are provided for inspecting,
integrating, testing, and validating official ULDA Core artifacts. They do not
grant unrestricted permission to create or validate ports, replacements, or
other functionally equivalent offerings; see [LICENSE.md](LICENSE.md).

## Additional documentation

- [ULDA Manifest](MANIFEST.md)
- [Build policy](docs/ULDA_BUILD.md)
- [Pack and version policy](docs/ULDA_PACK_POLICY.md)
- [Compact header](docs/ULDA_COMPACT_HEADER.md)
- [Test vectors](docs/ULDA_TEST_VECTORS.md)
- [Security policy](SECURITY.md)
- [License](LICENSE.md)

## Security status

Do not report suspected vulnerabilities through a public GitHub issue. Follow
the private reporting instructions in the [Security Policy](SECURITY.md).

A complete current origin package is secret state. Witness packages are public
and reveal the oldest block of the current origin without additional hashing.
Origin blocks must contain fresh random protocol values, not passwords, keys,
tokens, or other reusable application secrets. A verifier should persist the
last accepted witness and replace it atomically only after successful forward
verification.

The repository includes automated tests and deterministic official release
vectors, but it does not claim an independent cryptographic audit or a formal
security proof. Evaluate the construction and its fresh-tail behavior against
the threat model of the system that embeds this core. The normal generator
produces the recommended profile, but `verify()` accepts profile metadata from
the supplied witnesses and is not a complete policy for arbitrary
attacker-supplied packages. See the [security policy](SECURITY.md) for required
integration controls and known limitations.

## License

`ulda-core` is source-available under the
[ULDA Core Community Source License 1.0](LICENSE.md). Individual
non-commercial use and commercial integration by qualifying organizations with
Consolidated Gross Revenue of no more than USD 1,000,000 are permitted subject
to the license. Use above that threshold requires a separate commercial
license.

Regardless of revenue, using the Covered Materials to create or validate a
functionally equivalent ULDA offering requires a separate commercial license.
The full definitions, conditions, and mandatory-law exceptions are in
[LICENSE.md](LICENSE.md). This is not an OSI-approved open-source license.

The license covers only `ulda-core`; future ULDA libraries, servers, services,
and container products have separate terms.

## Repository and support

- Source: <https://github.com/ulda-io/ulda-core>
- Bug reports: <https://github.com/ulda-io/ulda-core/issues>
- Security reports: follow [SECURITY.md](SECURITY.md)
- Commercial licensing inquiries:
  [mark@shaposhnik.ch](mailto:mark@shaposhnik.ch)
- License: see [LICENSE.md](LICENSE.md)
