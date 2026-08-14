# Security Policy

ULDA Core is a low-level implementation of the ULDA state-lineage protocol.
It creates private origins, derives public witnesses, advances origins, and
checks directed witness transitions.

This policy describes the supported releases, vulnerability-reporting process,
security boundary of the core, and minimum responsibilities of an integrating
application. Protocol rules are defined in [MANIFEST.md](MANIFEST.md). API
usage is documented in [README.md](README.md).

## Supported versions

| Release | Status |
| --- | --- |
| Latest `1.0.x` release line | Supported |
| Prerelease and development builds earlier than `1.0.0` | Unsupported |
| Legacy packages published under an `ulda-sign` name | Unsupported |

Future high-level ULDA libraries, servers, and container distributions are
separate products and will have their own security policies.

## Reporting a vulnerability

Report suspected vulnerabilities privately by email:

- **Email:** mark@shaposhnik.ch
- **Subject:** `[SECURITY] ulda-core vulnerability report`

Do not open a public issue, discussion, or pull request for a suspected
vulnerability before coordinated disclosure. Ordinary bugs without security
impact may be reported through the public
[issue tracker](https://github.com/ulda-io/ulda-core/issues).

Include the affected version, a concise description, reproduction steps or a
minimal proof of concept, expected and observed behavior, potential impact,
and any known mitigation.

Use synthetic test data. Do not send production origins, credentials, access
tokens, personal data, or other secrets.

The maintainers will review the report, coordinate remediation when
appropriate, and coordinate public disclosure with the reporter whenever
practical. The time required to resolve an issue depends on its impact,
complexity, and compatibility requirements.

This reporting channel is for security matters only. For commercial licensing
inquiries, see [LICENSE.md](LICENSE.md).

## Scope of ULDA Core

This policy covers the official `ulda-core` source repository, npm package,
and distribution bundles. It covers the implementation required to:

- create a private origin with `New()`;
- derive a public witness with `sign()`;
- advance an origin with `stepUp()`;
- check a transition with `verify(previous, candidate)`;
- encode, decode, hash, and generate randomness as required by those
  operations.

Unofficial forks and modified packages, surrounding application code,
third-party implementations, storage systems, deployment infrastructure, and
future ULDA products are outside this policy unless a problem is caused by the
ULDA Core integration boundary itself.

## What `verify()` confirms

Verification is directed: the previously accepted witness is supplied first
and the candidate witness second.

For well-formed packages using an application-approved profile, a successful
`verify(previous, candidate)` result means that the candidate satisfies the
ULDA v1 hash-linked overlap rules at a permitted forward position relative to
the previous witness. The exact rules are defined in
[MANIFEST.md](MANIFEST.md).

Verification confirms only the required hash-linked overlap. It does not mean
that every byte of the candidate was authenticated by the previous witness.

This result is meaningful only when the previous witness has already been
accepted as trusted state for the intended user or stream. Both a `false`
result and an exception must be treated as rejection.

ULDA Core verifies continuation of a previously accepted witness chain, but it
does not establish ownership of the first witness. The integrating application
must obtain or store the first witness through a trusted mechanism and bind it
to the intended user or stream.

## What ULDA Core does not provide

ULDA Core is not:

- an encryption or key-management system;
- a user-identification, authentication, or authorization system;
- a general-purpose digital-signature or payload-authentication system;
- a storage or transport-security service;
- a replay-protection mechanism;
- a multi-writer coordination, fork-resolution, or consensus protocol.

Witnesses are public protocol values. Origins are private state and must be
protected by the integrating application. ULDA Core does not prescribe how an
origin is encrypted, stored, transferred, unlocked, or associated with a user.

The project includes automated tests and deterministic official release
vectors, but it does not claim an independent cryptographic audit or a formal
security proof.

## Integration requirements and known limitations

`ulda-core@1.0.x` is a low-level primitive, not a complete validation or
application-security layer. It must not be treated as the sole validation
boundary for externally supplied packages. Known limitations remain in input
validation and in the handling of non-default profiles, imported state, and
optional or compatibility features. This policy does not claim that these
limitations have been fixed. Some may be addressed in core updates, while
others may be handled by a future high-level library.

For normative profile and package-acceptance requirements, see
[Official profile conformance](MANIFEST.md#9-official-profile-conformance).

An integrating application must:

1. Protect the confidentiality and integrity of private origins.
2. Obtain the first witness through a trusted mechanism, bind it to the correct
   authenticated user or stream, and retain the last accepted witness.
3. Call `verify(previous, candidate)` in that order and replace retained state
   only after successful verification.
4. Validate externally supplied packages against a reviewed protocol profile
   before relying on `verify()` results or accepting them as application
   state. The recommended profile uses `compactV1`, Mode S, `N = 5`, SHA-256,
   and 256-bit origin blocks.
5. Reject unsupported, malformed, non-canonical, truncated, oversized, or
   otherwise unexpected packages before acceptance. Treat failures and
   exceptions as rejection.
6. Apply appropriate input-size, execution-time, memory, and concurrency
   limits.
7. Provide any required encryption, key derivation, storage protection,
   payload binding, replay policy, authorization, and multi-writer coordination
   outside ULDA Core.

Non-default profiles, compatibility features, imported state, custom hash
functions, and externally supplied code require separate review before
production use.

## Security updates

Security fixes are published as new supported npm versions and corresponding
GitHub releases. When public disclosure is appropriate, release notes or a
GitHub Security Advisory will identify affected versions and recommended
actions.

Production applications should use exact package versions and version-pinned
CDN URLs rather than mutable aliases such as `latest`.

Official release channels:

- GitHub releases: <https://github.com/ulda-io/ulda-core/releases>
- npm: <https://www.npmjs.com/package/ulda-core>

## Summary

ULDA Core confirms the directed continuation of a previously accepted witness
chain. It does not establish the identity of the chain owner, authenticate the
first witness, encrypt data, or bind witnesses to user payloads. These
properties, when needed, must be provided by the integrating application.
