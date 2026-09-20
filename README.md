# Digestory

Modern HTTP Digest Authentication for Ruby.

Digestory is a small, compatibility-aware implementation of RFC 7616 for modern Ruby. It provides a protocol-focused core for challenge parsing, digest calculation, authorization headers, session state, and Authentication-Info, plus an adapter for the historical `Net::HTTP::DigestAuth` API.

## Why

The long-standing `net-http-digest_auth` gem is a small RFC 2617-era implementation. Digestory keeps migration practical while providing a maintained RFC 7616-oriented implementation with SHA-256 and SHA-512/256 families, UTF-8 NFC handling, username hashing, `auth-int`, replay-state tracking, deterministic tests, malformed-input hardening, and HTTP interoperability tests.

## Install

~~~sh
gem install digestory
~~~

Gemfile:

~~~ruby
gem "digestory"
~~~

## Supported

- MD5 and MD5-sess for legacy interoperability.
- SHA-256 and SHA-256-sess.
- SHA-512-256 and SHA-512-256-sess using the standardized FIPS SHA-512/256 variant.
- `qop=auth` and `qop=auth-int`.
- UTF-8 credentials with NFC normalization.
- RFC 7616 username hashing and RFC 5987 `username*`.
- Authentication-Info with `nextnonce` and `rspauth` verification.
- Per-nonce nonce counts with replay-state protection.
- Legacy `Net::HTTP::DigestAuth` compatibility adapter.
- Ruby 3.3+.

### SHA-512/256 compatibility note

Digestory implements the actual SHA-512/256 algorithm defined by FIPS 180-4. Some RFC 7616 example values were published using a truncated SHA-512 calculation instead; Digestory intentionally follows the standardized SHA-512/256 construction so it interoperates with implementations that implement the algorithm by its FIPS definition.

## Native API

~~~ruby
require "digestory"

session = Digestory::Session.new(
  username: "Mufasa",
  password: "Circle of Life"
)

header = session.authorize(
  challenge: 'Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="..."',
  method: "GET",
  uri: "/dir/index.html"
)

# request["Authorization"] = header
~~~

The core API is strict by default: a Digest challenge without a supported `qop` is rejected. For an intentionally legacy peer, enable the compatibility behavior explicitly:

~~~ruby
session = Digestory::Session.new(
  username: "legacy-user",
  password: "legacy-password",
  allow_legacy_no_qop: true
)
~~~

When a server sends multiple Digest challenges, unsupported algorithms and unusable qop combinations are ignored during negotiation. A stronger usable algorithm is preferred by default; pass `prefer_stronger_algorithm: false` to follow the server's first supported challenge instead.

## Legacy API

~~~ruby
require "digestory/compat/net_http_digest_auth"

uri = URI("http://username:password@example.org/resource")
auth = Net::HTTP::DigestAuth.new
authorization = auth.auth_header(uri, www_authenticate, "GET")
~~~

The compatibility adapter is intended to ease migration from `net-http-digest_auth`; it does not promise byte-for-byte preservation of undocumented historical quirks.

## Request URI handling

Digestory preserves an explicit absolute-form request target such as:

~~~text
http://example.org/resource?x=1
~~~

A `URI` object uses Ruby's `request_uri` representation, which is the normal origin-form path and query used by `Net::HTTP`. The special request target `*` is preserved.

## Security

Digest Authentication does not replace TLS. It does not provide general confidentiality for HTTP messages; use HTTPS for transport security.

Do not treat the password or generated Authorization header as safe to log.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the protocol security model.

## Testing

~~~sh
ruby -Ilib -Itest -e 'Dir["test/**/*_test.rb"].sort.each { |f| require File.expand_path(f) }'
gem build digestory.gemspec
gem install --local digestory-0.1.0.gem --no-document
~~~

The test suite includes RFC/FIPS vectors, compatibility regressions, header-parser security tests, deterministic malformed-input fuzz smoke tests, a local HTTP interoperability server, and optional `curl --digest` interoperability.
