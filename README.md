# Digestory

Modern HTTP Digest Authentication for Ruby.

Digestory is a small, compatibility-aware implementation of RFC 7616. It provides a protocol-focused core for challenge parsing, digest calculation, authentication headers, session state, and Authentication-Info, plus an adapter for the historical Net::HTTP::DigestAuth API.

## Why

The long-standing net-http-digest_auth gem is tiny and widely used but implements an older RFC 2617-era model. Digestory keeps migration practical while providing a modern RFC 7616 implementation with stronger algorithms, UTF-8 support, username hashing, auth-int, deterministic tests, and security-focused parsing.

## Supported

- MD5 and MD5-sess for legacy interoperability.
- SHA-256 and SHA-256-sess.
- SHA-512-256 and SHA-512-256-sess.
- qop=auth and qop=auth-int.
- UTF-8 and RFC 7616 username hashing.
- Authentication-Info, including nextnonce and rspauth verification.
- Legacy Net::HTTP::DigestAuth compatibility adapter.
- Modern Ruby 3.3+.

Digest Authentication does not replace TLS. It does not provide general confidentiality for HTTP messages; use HTTPS for transport security.

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

## Legacy API

~~~ruby
require "digestory/compat/net_http_digest_auth"

uri = URI("http://username:password@example.org/resource")
auth = Net::HTTP::DigestAuth.new
authorization = auth.auth_header(uri, www_authenticate, "GET")
~~~

The compatibility adapter is intended to ease migration from net-http-digest_auth; it does not promise byte-for-byte preservation of undocumented historical quirks.

## Testing

~~~sh
ruby -Ilib -Itest -e 'Dir["test/**/*_test.rb"].sort.each { |f| require File.expand_path(f) }'
gem build digestory.gemspec
gem install --local digestory-0.1.0.gem --no-document
~~~

## Security

See SECURITY.md.
