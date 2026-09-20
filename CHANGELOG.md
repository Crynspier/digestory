# Changelog

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
