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

  def test_sha512_256_userhash_vector
    challenge = Digestory::Challenge.parse(<<~HEADER.gsub("\n", ""))
      Digest realm="api@example.org", qop="auth", algorithm=SHA-512-256,
      nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", charset=UTF-8, userhash=true
    HEADER
    username = "Jäsøn Doe"
    assert_equal "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec", Digestory::Digest.userhash(username: username, realm: challenge.realm, algorithm: challenge.algorithm, charset: challenge.charset)
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
    assert_equal "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd", result
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
