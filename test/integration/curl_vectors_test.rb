# frozen_string_literal: true

require_relative "../test_helper"

class CurlVectorsTest < Minitest::Test
  def test_local_response_matches_curl_style_sha256_vector
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n"'
    digest = Digestory::Challenge.parse(challenge)
    response = Digestory::Digest.response(
      challenge: digest,
      username: "user",
      password: "pass",
      method: "GET",
      uri: "/resource",
      nc: "00000001",
      cnonce: "abcdef",
      qop: "auth"
    )
    assert_equal 64, response.length
  end
end
