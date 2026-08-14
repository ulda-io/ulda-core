# ULDA Compact Header

## Purpose

This document describes the compact bit-level ULDA header used by the
`compactV1` package format.

`compactV1` is the ULDA 1.0 standard and default pack. Within official
development and permitted integrations, its lower-level header utility can also
support format tooling and future-version experiments, subject to the canonical
`compactV1` rules below and [LICENSE.md](../LICENSE.md).

See `ULDA_PACK_POLICY.md` for the current pack/version policy.

## Layout

```text
[0000][headerSize][inclusive][fields][0000][body]
```

The bitstream layout is:

```text
[prefix 4 bits][headerSize 8 bits][inclusive 8 bits][optional fields][suffix 4 bits][body]
```

`headerSize` is a `uint8` containing the full header size in bytes. It
includes the prefix nibble, `headerSize` byte, inclusive byte, optional fields,
and suffix nibble. It does not include the body.

Because the prefix and suffix are both 4 bits, the full header is byte-aligned.
The maximum header size is 255 bytes. The body starts at byte offset
`headerSize`.

## Inclusive Byte

| Bit | Mask | Meaning |
| --- | ---: | --- |
| 7 | `0x80` | `backupSize` field is present |
| 6 | `0x40` | `N` field is present |
| 5 | `0x20` | `algorithm` field is present |
| 4 | `0x10` | `age` field is present |
| 3 | `0x08` | backup descriptor bytes are present |
| 2 | `0x04` | mode X flag; if unset, mode is S |
| 1 | `0x02` | reserved future mode bit |
| 0 | `0x01` | backup active flag |

## Optional Field Order

Optional fields always appear in this exact order:

```text
if 0x80:
  backupSize: uint8

if 0x40:
  N: uint8

if 0x20:
  algorithm: uint8

if 0x10:
  age: uintBE

if 0x08:
  backupDescriptor: bytes[backupSize]
```

The low-level compact header utility supports `age` lengths of 4 or 8 bytes.
The parser infers the age length from `headerSize` and the known optional
field sizes. Runtime codecs may define stricter canonical policies.

## Defaults

When fields are absent, these defaults apply:

| Field | Default |
| --- | --- |
| `N` | `5` |
| `algorithm` | `2` (`SHA-256`) |
| `mode` | `S` |
| `age` | `0n` |
| `backupActive` | `false` |
| `backupSize` | `0` |
| `backupDescriptor` | empty `Uint8Array` |

Algorithm code namespace:

| Code | Algorithm |
| ---: | --- |
| `1` | `SHA-1` |
| `2` | `SHA-256` |
| `3` | `SHA-384` |
| `4` | `SHA-512` |
| `5` | `SHA3-256` |
| `6` | `SHA3-512` |
| `7` | `BLAKE3` |
| `8` | `WHIRLPOOL` |
| `255` | `CUSTOM` |

## Age Semantics

`age` is the absolute age/index carried by the header. The transition gap `g`
is computed outside this codec as:

```text
g = incomingAge - serverAge
```

The compact header codec only encodes and decodes the unsigned big-endian
integer. It does not perform verification or transition logic.

At the low-level header utility layer, the parser supports 4-byte and 8-byte
ages for tooling. Canonical `compactV1` is stricter: age is absent for `0n`,
and when present it is always a 4-byte unsigned big-endian integer.

## Backup Fields

Backup fields are reserved and can be transported by the low-level header
utility, but backup behavior is not defined by ULDA v1.

When a backup descriptor is present, `backupSize` must also be present and must
match the descriptor length.

The descriptor bytes are opaque to this module.

## compactV1 Codec

`createCompactV1Codec` is built on top of this compact header utility. It is the
ULDA 1.0 default runtime codec. The older simpleSig/v1 codec remains available
only through explicit legacy pack selection.

In compactV1 packages, header `age` maps to the package index. Origin package
bodies are still concatenated origin blocks, and witness package bodies are
still raw signature bytes. Canonical accepted `compactV1` packages do not set
backup or reserved future-mode fields; an integrating conformance gate must
reject them.

The canonical compactV1 age policy is fixed:

- absent age means index `0n`;
- present age is `uint32` big-endian;
- present age is always 4 bytes;
- 8-byte age is not part of compactV1 runtime;
- maximum age is `4294967295`;
- larger ages should use a future pack or version.

## Prefix and Suffix Nibbles

Both the prefix and suffix nibbles are currently `0000`.

They are a branded format marker and light obfuscation boundary. They are not
cryptographic security and must not be treated as authentication.

## Parser Notes

The parser is bit-level because the header starts and ends with 4-bit
sentinels. Optional fields are encoded as whole bytes but are shifted by four
bits in the surrounding byte stream.

The parser decodes only the header. It does not decode or interpret the body.
The body starts exactly at byte offset `headerSize`.

## Future Work

- Formalize the backup descriptor.
- Decide future pack/version handling for larger ages or package-kind markers.
