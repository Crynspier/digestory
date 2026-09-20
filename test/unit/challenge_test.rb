# frozen_string_literal: true

require_relative "../test_helper"

class ChallengeTest < Minitest::Test
  HEADER = <<~HEADER.gsub("\n", "")
    Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256,
    nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"
  HEADER

  def test_parses_rfc_challenge
    challenge = Digestory::Challenge.parse(HEADER)
    assert_equal "http-auth@example.org", challenge.realm
    assert_equal "SHA-256", challenge.algorithm
    assert_equal %w[auth auth-int], challenge.qop
    assert_equal "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", challenge.nonce
    assert_equal "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS", challenge.opaque
  end

  def test_parses_multiple_digest_challenges
    header = 'Digest realm="a", nonce="1", algorithm=MD5, qop="auth", Digest realm="b", nonce="2", algorithm=SHA-256, qop="auth"'
    challenges = Digestory::Challenge.parse_all(header)
    assert_equal 2, challenges.length
    assert_equal "MD5", challenges[0].algorithm
    assert_equal "SHA-256", challenges[1].algorithm
  end

  def test_selects_preferred_supported_qop
    challenge = Digestory::Challenge.parse(HEADER)
    assert_equal "auth", challenge.choose_qop(preference: %w[auth auth-int])
    assert_equal "auth-int", challenge.choose_qop(preference: ["auth-int"])
  end

  def test_ignores_non_digest_challenges
    header = 'Basic realm="b", Digest realm="d", qop="auth", algorithm=SHA-256, nonce="n"'
    assert_equal ["d"], Digestory::Challenge.parse_all(header).map(&:realm)
  end
end
