# ULDA Manifest

- **Protocol family:** Universal Linear Data Authentication (ULDA) v1
- **Implementation profile:** ULDA Core JavaScript (`UldaSign`), `compactV1`
- **Package and version:** `ulda-core@1.0.1`
- **Status:** normative release specification with integration conformance
  requirements
- **Revision:** 2026-08-17

This document defines the behavior implemented by this repository. It replaces
earlier conceptual descriptions wherever they disagree with the code, the
committed test vectors, or the rules below.

The mathematical operations and wire formats are implementation-aligned. Some
profile-validation requirements marked `MUST` are conformance requirements for
the complete integrating system rather than checks enforced by every low-level
JavaScript entry point. The JavaScript core is therefore not, by itself, a
complete hostile-input conformance or security gate; see the
[Security Policy](SECURITY.md).

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as described by
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they
appear in uppercase.

## 1. Purpose and boundaries

ULDA checks directed forward lineage between compact states using cryptographic
hash commitments. A producer holds a private rolling window and publishes a
witness for the current window. A verifier retains the last accepted witness
and checks whether a candidate is consistent with the required hash-linked
overlap at an allowed future position.

In the official JavaScript API, `verify(previous, candidate)` is stateless.
The surrounding application is responsible for retaining the last accepted
witness and updating it atomically after successful verification.

This manifest covers the low-level core only. A future high-level ULDA library
and any ULDA server or container distribution are separate products with their
own APIs, release cycles, security policies, and licenses.

ULDA is not:

- encryption;
- a general-purpose digital-signature algorithm;
- a public-key infrastructure;
- a key derivation or key-management system;
- a consensus or multi-writer coordination protocol;
- a message, payload, timestamp, account, or stream-identity binding;
- an authenticity mechanism for the first witness.

Those functions MUST be supplied by the surrounding application when they are
required. In particular, accepting the first witness is a trust-establishment
decision outside ULDA.

## 2. Terms and notation

- `f` is the selected cryptographic hash function.
- `f^g(x)` applies `f` to `x` exactly `g` times; `f^0(x) = x`.
- `||` is byte concatenation.
- `N` is the rolling-window height. A valid profile uses `2 <= N <= 255`; the
  default is `5`.
- `k` is the unsigned state index, also called age.
- `B_k = [b_{k,0}, ..., b_{k,N-1}]` is the private origin window at age `k`.
- `W_k = [w_{k,0}, ..., w_{k,N-1}]` is the public witness at age `k`.
- `g` is a forward gap: `candidate.age - previous.age`.

The JavaScript API represents age as `bigint`. The `compactV1` runtime limits
encoded age to an unsigned 32-bit integer.

Origin-block size is measured in bits and MUST be positive and divisible by
eight. The current JavaScript configuration layer trusts callers to enforce
these profile constraints. The integrating application MUST enforce both the
`N` and origin-size constraints before accepting externally supplied state.

## 3. Origin lifecycle

`New(k)` creates `N` independent blocks with a cryptographically secure random
generator and encodes them as a private origin package at age `k`.

`stepUp(B_k)` constructs the next window as follows:

```text
b_(k+1,i)   = b_(k,i+1)       for 0 <= i < N - 1
b_(k+1,N-1) = fresh_random()
```

It then encodes the result at age `k + 1`.

An implementation MUST use a cryptographically secure source of randomness for
new origin blocks. Applications MUST protect origin packages as secrets, MUST
NOT publish them as witnesses, and SHOULD retire superseded origins after the
required state transition is durably committed.

`stepUp` is functional at the public API boundary: it returns a new package and
does not mutate the supplied package. Reusing an older origin to create several
successors creates branches. ULDA itself does not choose between them.

## 4. Witness construction

The current wire witness is a vector of `N` commitment blocks. It is not the
serialization of every cell in a triangular matrix.

### 4.1 Mode S — skippable

For each position `i`:

```text
w_(k,i) = f^i(b_(k,i))        for 0 <= i < N
```

Mode S therefore publishes the diagonal commitments of the conceptual hash
ladder. It supports verification across a bounded forward gap.

### 4.2 Mode X — adjacent-only

Define a cross-linked reduction:

```text
L_(k,0,i) = b_(k,i)

L_(k,d,i) = f(L_(k,d-1,i) || L_(k,d-1,i+1))
             for 1 <= d < N and 0 <= i < N - d

w_(k,d) = L_(k,d,0)           for 0 <= d < N
```

Mode X publishes the left edge of that reduction and permits only adjacent
verification.

## 5. Verification

The semantic API is directed:

```text
verify(previousWitness, candidateWitness)
```

Before mode-specific verification, the implementation compares `N`, mode, and
hash-algorithm metadata. It returns `false` when they differ. It also returns
`false` unless `candidate.age > previous.age`. Decodable but incompatible
packages return `false`; malformed packages and unavailable hash
implementations may throw. Integrators MUST treat both `false` and exceptions
as rejection.

### 5.1 Mode S

Let `g = candidate.age - previous.age`. Verification MUST reject unless:

```text
1 <= g < N
```

It accepts exactly when all overlapping commitments satisfy:

```text
f^g(candidate[i]) == previous[i + g]
for every i in [0, N - g - 1]
```

Consequently, a mode-S witness with `N = 5` can verify gaps `1`, `2`, `3`, and
`4`, but not `5` or greater.

The final `g` blocks of the candidate witness have no overlap with the previous
witness and are not checked by this transition. This fresh-tail rule is part of
the current v1 construction; it MUST NOT be described as whole-witness
authentication by the predecessor.

### 5.2 Mode X

Verification MUST reject unless `g = 1`. The `1.0.x` JavaScript implementation
also requires equal total witness-body lengths and a total body length divisible
by `N`. This makes non-default Mode X profiles whose origin-block length differs
from the digest length subject to an additional implementation limitation.
Within the accepted profile, verification succeeds when:

```text
f(previous[d - 1] || candidate[d - 1]) == previous[d]
for every d in [1, N - 1]
```

The final block of the candidate witness is not checked by its predecessor. As
with mode S, later transitions constrain commitments that were introduced in a
fresh tail.

### 5.3 State-machine rule

A verifier SHOULD keep only the last accepted witness for each externally
identified stream. It SHOULD perform the following operation atomically:

1. Load the last accepted witness.
2. Verify it against the candidate in that order.
3. If verification succeeds, replace the stored witness with the candidate.

Same-age replay and rollback are rejected by directed age comparison. Two
competing successors may each verify against the same predecessor, so the
application MUST provide serialization, conflict handling, or consensus when
more than one writer can advance a stream.

## 6. The `compactV1` package

The canonical protocol value is a byte string. Hex and Base64 are transport
representations and do not change package semantics.

An origin package and a witness package both contain:

```text
[compact header][body]
```

There is no package-kind field in v1. The calling operation determines whether
the body is decoded as an origin or a witness. Passing the wrong package kind
is not guaranteed to be rejected by the container alone.

### 6.1 Header bit layout

```text
[prefix:4][headerSize:8][flags:8][optional fields...][suffix:4]
```

- `prefix` MUST be `0000`.
- `headerSize` is the total header length in bytes and MUST fit `uint8`.
- `suffix` MUST be `0000`.
- Optional fields begin at bit offset `20` and are byte-sized even though they
  are positioned on a half-byte boundary.

The flags byte uses these bits:

| Mask | Meaning |
| --- | --- |
| `0x80` | backup-size field is present |
| `0x40` | `N` field is present |
| `0x20` | algorithm field is present |
| `0x10` | age field is present |
| `0x08` | backup descriptor is present |
| `0x04` | mode X; when clear, mode S |
| `0x02` | reserved future-mode bit |
| `0x01` | backup-active marker |

Present optional fields are serialized in this order:

```text
backupSize, N, algorithm, age, backupDescriptor
```

The low-level header codec can transport backup fields, but ULDA v1 defines no
backup semantics. A canonical accepted `compactV1` package MUST have the
backup-size, backup-descriptor, backup-active, and future-mode flags absent or
clear. A low-level decoder may expose these fields for tooling; an integrating
conformance gate MUST reject them.

### 6.2 Defaults and canonical age

The omitted-field defaults are:

| Field | Default |
| --- | --- |
| `N` | `5` |
| algorithm | SHA-256, code `0x02` |
| mode | S |
| age | `0` |

A nonzero age in `compactV1` MUST be exactly four unsigned, big-endian bytes.
Canonical age `0` MUST be represented by an absent age field. The low-level
header utility can parse an explicit four-byte zero and eight-byte ages, but an
integrating conformance gate MUST reject those non-canonical representations.
The runtime rejects ages greater than `4294967295` and rejects eight-byte ages.

### 6.3 Algorithm identifiers

| Code | Identifier | Runtime availability |
| --- | --- | --- |
| `0x01` | SHA-1 | Web Crypto; compatibility only |
| `0x02` | SHA-256 | Web Crypto; default |
| `0x03` | SHA-384 | Web Crypto |
| `0x04` | SHA-512 | Web Crypto |
| `0x05` | SHA3-256 | External implementation required |
| `0x06` | SHA3-512 | External implementation required |
| `0x07` | BLAKE3 | External implementation required |
| `0x08` | WHIRLPOOL | External implementation required |
| `0xff` | Custom | Out-of-band agreement required |

An identifier in the header does not guarantee that the local runtime has an
implementation. Custom code `0xff` is not globally self-describing; every
participant MUST agree on the custom function and output parameters outside
the package.

### 6.4 Body layout

An origin body is the direct concatenation of `N` equal-sized private blocks:

```text
b_(k,0) || b_(k,1) || ... || b_(k,N-1)
```

A witness body is the direct concatenation of its `N` public commitment blocks:

```text
w_(k,0) || w_(k,1) || ... || w_(k,N-1)
```

The first witness block has the configured origin-block length. The remaining
body is divided equally among the other `N - 1` commitment blocks. Origin size
is not encoded in `compactV1`; all participants MUST configure it consistently.

## 7. Legacy `simpleSig` compatibility

`simpleSig` preserves the earlier package header:

```text
[0x00][headerLength][N][modeCode][algorithmCode][minimal age bytes][0x00][body]
```

Age `0` occupies one zero byte in this layout. The body semantics are the same
origin or witness vectors described above.

`simpleSig` is selected explicitly with `sign.pack = "simpleSig"`; `"v1"` is a
legacy alias. `compactV1` and `simpleSig` MUST NOT be silently guessed or decoded
as one another. Format selection is an out-of-band stream property.

## 8. Security considerations

### 8.1 Private and public material

A complete current origin package contains the material needed to derive
witnesses and future overlap commitments and MUST be treated as secret state.
Witness packages are designed to be public. In both modes,
`w_(k,0) = b_(k,0)`, so a witness publishes the oldest block of the current
origin without additional hashing. Successive witnesses reveal blocks from an
older window as it advances.

Origin blocks therefore MUST be fresh random protocol values and MUST NOT
contain passwords, encryption keys, API tokens, or other reusable application
secrets. Secret origin state does not imply permanent secrecy of every block,
key hiding, forward secrecy, or automatic post-compromise recovery.

JavaScript does not provide a reliable guarantee that retired secret bytes are
immediately erased from memory. Applications with stronger erasure
requirements need an execution and key-storage design that provides them.

### 8.2 Fresh-tail limitation

Verification authenticates only the overlap between two witnesses. A candidate
contains a fresh tail that the predecessor cannot authenticate. For mode S the
unchecked tail length equals the gap; for mode X it is one block.

Applications MUST NOT interpret `verify(previous, candidate) === true` as proof
that every byte of the candidate was committed by `previous`. Whether the
delayed constraint supplied by later states is sufficient depends on the
application protocol and threat model.

### 8.3 No payload binding

The `UldaSign` API does not accept a message argument and does not bind a
witness to application data. If lineage must authenticate data, the
surrounding protocol MUST define an unambiguous binding, replay rules, and
domain separation and MUST subject that construction to independent review.

### 8.4 Algorithm and parameter policy

SHA-256 with `N = 5`, 256-bit origin blocks, and `compactV1` is the default
implementation profile. SHA-1 SHOULD NOT be used for new deployments. External
hash functions MUST provide stable byte output of the configured size and
SHOULD be reviewed for the intended security level.

Changing `N`, mode, hash, origin size, or package format inside an existing
stream can make subsequent packages unverifiable. Parameter migration requires
an application-level protocol.

### 8.5 Claims and review status

Fresh random tail blocks limit how much an older origin directly reveals about
future appended material. This document does not elevate that observation into
a formal post-compromise-security claim.

The repository includes unit tests and deterministic official release vectors,
but it does not claim an independent cryptographic audit or a formal security
proof. Deployments SHOULD obtain expert review appropriate to their risk.

## 9. Official profile conformance

A deployment using the official ULDA Core and claiming conformance with its
ULDA v1 profile MUST, through the core or integrating application:

1. Provide at least one of mode S or mode X exactly as defined above.
2. Enforce directed `previous -> candidate` verification.
3. Reject equal or decreasing ages.
4. Enforce `1 <= g < N` for mode S and `g = 1` for mode X.
5. Enforce canonical `compactV1` uint32 age handling.
6. Preserve the `N`-block body layout.
7. Enforce `2 <= N <= 255` and a positive, byte-aligned origin-block size.
8. Reject reserved future-mode and backup fields in canonical accepted v1
   packages.
9. Use cryptographically secure randomness when generating or advancing
   origins.
10. Match the committed deterministic vectors for each claimed mode and pack.

Where the low-level core does not perform one of these checks, the integrating
application MUST perform it before accepting a package.

For official releases and permitted integration validation, the wire format and
files in `test-vectors/` are canonical release fixtures. JavaScript module
boundaries are implementation details. Use of this Manifest, the protocol
documentation, and test vectors to develop or validate ports, replacements, or
other functionally equivalent offerings is governed by [LICENSE.md](LICENSE.md).

## 10. Revision notes

This revision aligns the manifest with the current implementation:

- witnesses serialize one vector of `N` commitment blocks rather than an
  `N(N+1)/2` triangular matrix;
- the rolling origin shifts retained blocks and appends one fresh block per
  step;
- verification order is explicitly old-to-new;
- the unchecked fresh-tail behavior is documented;
- `compactV1` is the default package and its actual header is specified;
- `simpleSig` is retained as an explicit legacy format;
- payload binding, stream identity, initial trust, and writer coordination are
  explicitly outside the protocol;
- security claims not established by the implementation or an external review
  have been removed or narrowed.
