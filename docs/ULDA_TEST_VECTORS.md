# ULDA Test Vectors

## Purpose

The committed ULDA test vectors are deterministic release fixtures for the
official JavaScript source, generated bundles, and permitted integration tests.

They verify the official wire format, package decoding, signing, and the
directed `verify(previousWitness, candidateWitness)` contract across official
artifact forms.

## Safety

The vectors use synthetic deterministic origin blocks only. They are not real
private user secrets and must not be reused as production secrets.

Origin packages in the vector file intentionally contain those synthetic test
blocks so maintainers and integrators can validate the exact wire encoding of
official artifacts.

## Deterministic Blocks

The default vector parameters are:

- `N = 5`
- `originSize = 256`
- `blockLen = 32`
- `hash = SHA-256`
- `exportFormat = hex`

For block number `k`, byte `j` is:

```text
byte[j] = (k * 32 + j) & 0xff
```

So block `0` is `00 01 02 ... 1f`, block `1` is `20 21 22 ... 3f`, and so on.

Origin at age `A` is:

```text
[block A, block A + 1, block A + 2, block A + 3, block A + 4]
```

## Coverage

The vector file covers both packs:

- `compactV1`, the ULDA 1.0 standard/default pack
- `simpleSig`, the explicit legacy compatibility pack

It covers both modes:

- `S`
- `X`

It records origins and witnesses at ages `0`, `1`, `2`, `4`, and `5`.

The expected forward-only verify matrix covers:

- forward adjacent verification;
- reversed-order rejection;
- mode S skip where gap is less than `N`;
- mode S rejection where gap is greater than or equal to `N`;
- mode X adjacent-only behavior;
- same-step rejection.

## Regenerate

```bash
npm run generate:vectors
```

The generator does not use random values or timestamps. It writes stable
pretty-printed JSON to:

```text
test-vectors/ulda-v1-vectors.json
```

## Verify

```bash
npm run verify:vectors
npm test
```

The verifier signs each committed origin package and checks that the resulting
witness exactly matches the committed witness. It also checks the listed verify
pairs and decoded metadata.

The verifier prints only safe summaries: vector id, pack, mode, and assertion
counts. It does not print origin packages, witness packages, raw blocks, or
private material.

## Policy

Do not silently update vectors when behavior changes.

Vector changes should be reviewed as protocol changes unless they are clearly
limited to non-semantic metadata. Maintainers and integrators should use the
wire format and these vectors to validate official releases and permitted
integrations.

Use of the vectors to develop or validate ports, replacements, or other
functionally equivalent offerings is governed by [LICENSE.md](../LICENSE.md).

Directed verification is a breaking API behavior change from earlier behavior
that accepted reversed arguments. It changes reverse-case expectations only;
the wire format and encoded origin and witness fixtures remain unchanged.
