# frozen_string_literal: true

require_relative "../test_helper"

class DigestTest < Minitest::Test
  SHA256_CHALLENGE = Digestory::Challenge.parse(<<~HEADER.gsub("\n", ""))
    Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256,
    nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
  HEADER

  def test_rfc_sha256_vector
    result = Digestory::Digest.response(
      challenge: SHA256_CHALLENGE,
      username: "Mufasa",
      password: "Circle of Life",
      method: "GET",
      uri: "/dir/index.html",
      nc: "00000001",
      cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
      qop: "auth"
    )
    assert_equal "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", result
  end

  def test_rfc_md5_vector
    challenge = Digestory::Challenge.parse('Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"')
    result = Digestory::Digest.response(
      challenge: challenge,
      username: "Mufasa",
      password: "Circle of Life",
      method: "GET",
      uri: "/dir/index.html",
      nc: "00000001",
      cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
      qop: "auth"
    )
    assert_equal "8ca523f5e9506fed4657c9700eebdbec", result
  end

  def test_sha512_256_uses_standard_fips_variant
    assert_equal "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", Digestory::Algorithm.digest("SHA-512-256", "abc")
  end

  def test_sha512_256_rfc_example_uses_standard_variant
    challenge = Digestory::Challenge.parse(<<~HEADER.gsub("\n", ""))
      Digest realm="api@example.org", qop="auth", algorithm=SHA-512-256,
      nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", charset=UTF-8, userhash=true
    HEADER
    username = "Jäsøn Doe"
    assert_equal "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b", Digestory::Digest.userhash(username: username, realm: challenge.realm, algorithm: challenge.algorithm, charset: challenge.charset)
    result = Digestory::Digest.response(
      challenge: challenge,
      username: username,
      password: "Secret, or not?",
      method: "GET",
      uri: "/doe.json",
      nc: "00000001",
      cnonce: "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v",
      qop: "auth"
    )
    assert_equal "3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5", result
  end

  def test_auth_int_includes_entity_body
    challenge = Digestory::Challenge.parse('Digest realm="r", qop="auth-int", algorithm=SHA-256, nonce="n"')
    auth = Digestory::Digest.response(
      challenge: challenge,
      username: "u",
      password: "p",
      method: "POST",
      uri: "/x",
      nc: "00000001",
      cnonce: "c",
      qop: "auth-int",
      entity_body: "hello"
    )
    no_auth_int = Digestory::Digest.response(
      challenge: challenge,
      username: "u",
      password: "p",
      method: "POST",
      uri: "/x",
      nc: "00000001",
      cnonce: "c",
      qop: "auth-int",
      entity_body: "world"
    )
    refute_equal auth, no_auth_int
  end

  def test_utf8_credentials_are_nfc_normalized
    challenge = Digestory::Challenge.parse('Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n", charset=UTF-8')
    composed = "é"
    decomposed = "é"
    composed_hash = Digestory::Digest.userhash(username: composed, realm: challenge.realm, algorithm: challenge.algorithm, charset: challenge.charset)
    decomposed_hash = Digestory::Digest.userhash(username: decomposed, realm: challenge.realm, algorithm: challenge.algorithm, charset: challenge.charset)
    assert_equal composed_hash, decomposed_hash
  end

  def test_sess_algorithm
    challenge = Digestory::Challenge.parse('Digest realm="r", qop="auth", algorithm=SHA-256-sess, nonce="n"')
    result = Digestory::Digest.response(
      challenge: challenge,
      username: "u",
      password: "p",
      method: "GET",
      uri: "/",
      nc: "00000001",
      cnonce: "c",
      qop: "auth"
    )
    assert_equal 64, result.length
  end
end


class DigestInputValidationTest < Minitest::Test
  def test_sess_algorithm_requires_cnonce
    challenge = Digestory::Challenge.parse('Digest realm="r", nonce="n", algorithm=SHA-256-sess, qop="auth"')
    assert_raises(Digestory::InvalidHeader) do
      Digestory::Digest.response(
        challenge: challenge,
        username: "u",
        password: "p",
        method: "GET",
        uri: "/",
        nc: "00000001",
        cnonce: nil,
        qop: "auth"
      )
    end
  end
end


class CnonceValidationTest < Minitest::Test
  def test_rejects_non_ascii_cnonce
    challenge = Digestory::Challenge.parse('Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"')
    assert_raises(Digestory::InvalidHeader) do
      Digestory::Digest.response(
        challenge: challenge,
        username: "u",
        password: "p",
        method: "GET",
        uri: "/",
        nc: "00000001",
        cnonce: "café",
        qop: "auth"
      )
    end
  end
end
