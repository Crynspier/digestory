# frozen_string_literal: true

require_relative "test_helper"
require "digestory/compat/net_http_digest_auth"
require "uri"

class CompatibilityTest < Minitest::Test
  def test_legacy_public_helpers
    auth = Net::HTTP::DigestAuth.new
    assert_equal 1, auth.next_nonce
    assert_match(/\A[\x20-\x7E]+\z/, auth.make_cnonce)
  end

  def test_legacy_api_shape_and_header
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://Mufasa:#{URI::DEFAULT_PARSER.escape('Circle of Life')}@example.org/dir/index.html")
    challenge = 'Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
    header = auth.auth_header(uri, challenge, "GET")
    assert_equal "Digest", header.split.first
    assert_includes header, "algorithm=SHA-256"
    assert_match(/nc=[0-9a-f]{8}/, header)
  end

  def test_iis_qop_compatibility
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://u:p@example.org/")
    header = auth.auth_header(uri, 'Digest realm="r", qop="auth", algorithm=MD5, nonce="n"', "GET", true)
    assert_includes header, 'qop="auth"'
  end
end


class CompatibilityCredentialTest < Minitest::Test
  def test_preserves_plus_in_uri_credentials
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://u+v:p+q@example.org/")
    header = auth.auth_header(uri, 'Digest realm="r", qop="auth", algorithm=MD5, nonce="n"', "GET")
    assert_includes header, 'username="u+v"'
  end
end


class CompatibilityCredentialValidationTest < Minitest::Test
  def test_requires_uri_password
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://u@example.org/")
    assert_raises(Digestory::MissingCredential) do
      auth.auth_header(
        uri,
        'Digest realm="r", qop="auth", algorithm=MD5, nonce="n"',
        "GET"
      )
    end
  end
end


class CompatibilityAuthIntTest < Minitest::Test
  def test_can_opt_into_auth_int
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://u:p@example.org/upload")
    header = auth.auth_header(
      uri,
      'Digest realm="r", qop="auth-int", algorithm=SHA-256, nonce="n"',
      "POST",
      false,
      entity_body: "hello",
      qop: "auth-int"
    )
    assert_includes header, "qop=auth-int"
    assert_match(/nc=[0-9a-f]{8}/, header)
  end

  def test_legacy_adapter_ignores_auth_int_when_auth_is_available
    auth = Net::HTTP::DigestAuth.new
    uri = URI("http://u:p@example.org/")
    header = auth.auth_header(
      uri,
      'Digest realm="r", qop="auth, auth-int", algorithm=SHA-256, nonce="n"',
      "GET"
    )
    assert_includes header, "qop=auth"
  end
end
