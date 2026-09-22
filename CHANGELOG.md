# Changelog

## 0.1.1 - 2026-09-22

- Added immutable request-specific authorization contexts for concurrent authentication exchanges.
- Added explicit `verify_authentication_info` and `authorize_from` APIs so response verification and `nextnonce` chaining do not depend on global last-request state.
- Changed nonce tracking to an atomic per-nonce/protection-state counter, preserving nonce-count correctness across concurrent requests.
- Added optional RFC 7616 `domain` protection-space parsing and `Challenge#protects?`, with opt-in session enforcement.
- Made empty `auth-int` bodies valid and added precomputed `entity_digest` support for large or non-replayable request bodies.
- Reject non-seekable IO bodies for `auth-int` instead of silently consuming a stream that cannot be replayed.
- Improved unsupported-algorithm diagnostics when a header contains Digest challenges but none are usable.
- Tightened legacy URI credential validation and documented the compatibility adapter's intentionally narrower behavior.
- Expanded regression coverage for concurrent verification, `nextnonce`, protection spaces, qop parsing, unsupported algorithms, and replay-safe `auth-int`.
- Made test and release workflows version-agnostic instead of hard-coding the previous gem version.
- Clarified retry, stale-nonce, concurrency, and external-interoperability behavior in the documentation.

## 0.1.0 - 2026-09-20

- Initial production release.
- RFC 7616-oriented Digest Authentication core.
- MD5/MD5-sess, SHA-256/SHA-256-sess, and standardized SHA-512/256/SHA-512-256-sess support.
- `qop=auth` and `qop=auth-int`.
- Strict qop-required session behavior by default, with explicit legacy no-qop opt-in.
- UTF-8 credential NFC normalization and RFC 7616 username hashing.
- RFC 5987 `username*` support.
- Per-nonce nonce-count tracking with nonce-count exhaustion protection.
- Authentication-Info parsing with `nextnonce`, `rspauth`, and request-context validation.
- Unsupported Digest algorithms and unusable challenges are ignored during negotiation.
- Effective request-target handling for origin-form, absolute-form, and `*`.
- Legacy `Net::HTTP::DigestAuth` compatibility adapter, including IIS qop quoting behavior.
- RFC/FIPS vectors, parser security regressions, deterministic malformed-input fuzz smoke tests, local HTTP interoperability, and optional curl interoperability tests.
