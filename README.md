# Digestory

Modern HTTP Digest Authentication for Ruby.

Digestory is a small, compatibility-aware implementation of RFC 7616 for modern Ruby. It provides a protocol-focused core for challenge parsing, digest calculation, authorization headers, request-specific authentication contexts, session state, and Authentication-Info, plus an adapter for the historical `Net::HTTP::DigestAuth` API.

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
- Immutable request-specific authorization contexts for concurrent authentication exchanges.
- Optional Digest protection-space (`domain`) enforcement with fail-closed origin handling.
- Bounded replay-state growth for long-lived sessions.
- Legacy `Net::HTTP::DigestAuth` compatibility adapter with bounded credential/session caching.
- Ruby 3.3+.

### SHA-512/256 compatibility note

Digestory implements the actual SHA-512/256 algorithm defined by FIPS 180-4. Some RFC 7616 example values were published using a truncated SHA-512 calculation instead; Digestory intentionally follows the standardized SHA-512/256 construction so it interoperates with implementations that implement the algorithm by its FIPS definition.

## Native API

The simple API remains compatible with 0.1.0:

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

For concurrent in-flight requests, use the request-specific context API:

~~~ruby
session = Digestory::Session.new(
  username: "Mufasa",
  password: "Circle of Life"
)

context = session.authorize_with_context(
  challenge: www_authenticate,
  method: "GET",
  uri: "/dir/index.html"
)

request["Authorization"] = context.header

# Later, for the matching response:
info = session.verify_authentication_info(
  context,
  response["authentication-info"],
  response_body: response.body
)
~~~

Each `AuthorizationContext` is immutable and contains the exact challenge, nonce, nonce-count, cnonce, request URI, and digest response used for that request. Verification therefore does not depend on a single global "last request" slot.

When a server returns `nextnonce`, the modern API keeps that value explicit:

~~~ruby
next_context = session.authorize_from(
  context,
  method: "GET",
  uri: "/next",
  nonce: info.nextnonce
)
~~~

This avoids accidentally applying a nonce received for one concurrent exchange to another exchange.

### QOP and negotiation

The core API is strict by default: a Digest challenge without a supported `qop` is rejected. For an intentionally legacy peer, enable the compatibility behavior explicitly:

~~~ruby
session = Digestory::Session.new(
  username: "legacy-user",
  password: "legacy-password",
  allow_legacy_no_qop: true
)
~~~

When a server sends multiple Digest challenges, unsupported algorithms and unusable qop combinations are ignored during negotiation. By default, Digestory keeps the first usable protection space and prefers the strongest supported algorithm within that space; pass `prefer_stronger_algorithm: false` to follow the server's first supported challenge instead.

If `Digestory::Challenge.parse` sees Digest challenges but every Digest challenge uses an unsupported algorithm, it raises `Digestory::UnsupportedAlgorithm` so callers can distinguish that case from a header containing no Digest challenge at all.

### Protection spaces

Digestory parses the RFC 7616 `domain` parameter and exposes:

~~~ruby
challenge.protects?("/private/report")
challenge.protects?(
  "/private/report",
  base_uri: "https://example.org"
)
~~~

Optional session enforcement is available:

~~~ruby
session = Digestory::Session.new(
  username: "u",
  password: "p",
  enforce_domain: true
)
~~~

When enforcement is enabled, Digestory fails closed if a relative request target cannot be associated with an absolute origin. Without `enforce_domain`, `domain` remains metadata and applications can make their own protection-space decisions. This is useful for legacy integrations where a server's domain declaration is incomplete or non-standard.

### `auth-int` request bodies

An empty entity body is represented by `entity_body: nil` and is valid for `auth-int`.

For a replayable IO, Digestory temporarily reads and restores the original position. Non-seekable streams are rejected so authentication does not silently consume a request body that the HTTP client cannot replay.

Long-lived sessions bound the number of distinct nonce states by default. Configure `max_nonce_states:` when a larger working set is required; when the bound is reached, Digestory refuses a new nonce rather than evicting state and risking nonce-count reuse.

For large or non-replayable bodies, provide the already-computed digest:

~~~ruby
entity_digest = Digestory::Algorithm.digest("SHA-256", "contents of body")

context = session.authorize_with_context(
  challenge: challenge,
  method: "POST",
  uri: "/upload",
  entity_digest: entity_digest
)
~~~

The digest must be the hexadecimal digest produced by the selected Digest algorithm. Do not provide `entity_body` and `entity_digest` together; doing so raises `Digestory::InvalidEntityBody` to avoid silently authenticating a digest that differs from the supplied body.

## Legacy API

~~~ruby
require "digestory/compat/net_http_digest_auth"

uri = URI("http://username:password@example.org/resource")
auth = Net::HTTP::DigestAuth.new
authorization = auth.auth_header(uri, www_authenticate, "GET")
~~~

The compatibility adapter is intended to ease migration from `net-http-digest_auth`. It deliberately preserves the historical API and its narrower behavior; use `Digestory::Session` for the modern RFC 7616 feature set, including `auth-int`, username hashing, `username*`, and Authentication-Info verification.

The legacy adapter expects both URI user and password fields to be present. URI credentials are a legacy transport mechanism and should not be logged; prefer explicit username/password handling in new applications.

## Request URI handling

Digestory preserves an explicit absolute-form request target such as:

~~~text
http://example.org/resource?x=1
~~~

A `URI` object uses Ruby's `request_uri` representation, which is the normal origin-form path and query used by `Net::HTTP`. The special request target `*` is preserved.

## HTTP retry and `stale=true`

The low-level API intentionally does not automatically retry arbitrary HTTP requests. Applications or HTTP-client integrations remain responsible for deciding whether a request body can be replayed, limiting retry attempts, and handling transport-specific behavior.

A `Challenge` exposes `stale?`. When a server returns a new stale challenge, pass that challenge into `authorize` or `authorize_with_context` to construct the retry credentials without prompting for new credentials.

## Security

Digest Authentication does not replace TLS. It does not provide general confidentiality for HTTP messages; use HTTPS for transport security.

Do not treat the password or generated Authorization header as safe to log.

The legacy `authorize` / `update_authentication_info` API keeps a compatibility "last request" slot. It is safe for sequential exchanges, but concurrent callers requiring response verification should use `authorize_with_context` and `verify_authentication_info`.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the protocol security model.

## Testing

~~~sh
ruby -Ilib -Itest -e 'Dir["test/**/*_test.rb"].sort.each { |f| require File.expand_path(f) }'
gem build digestory.gemspec
gem install --local digestory-0.1.2.gem --no-document
~~~

The test suite includes RFC/FIPS vectors, compatibility regressions, header-parser security tests, deterministic malformed-input fuzz smoke tests, protection-space and request-context regressions, local HTTP interoperability, and optional `curl --digest` interoperability.

The suite also covers SHA-512/256 digest construction, replay-safe `auth-int` handling, URI rejection, bounded session state, and compatibility-cache hygiene. External-server behavior remains environment-dependent, so local integration tests are supplemented by independent protocol vectors and parser/security regressions.
