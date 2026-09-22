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


class ChallengeNegotiationTest < Minitest::Test
  def test_ignores_unsupported_digest_algorithm
    header = 'Digest realm="bad", nonce="bad", algorithm=SHA-1, qop="auth", Digest realm="good", nonce="good", algorithm=SHA-256, qop="auth"'
    challenges = Digestory::Challenge.parse_all(header)
    assert_equal ["SHA-256"], challenges.map(&:algorithm)
    assert_equal "good", challenges.first.realm
  end
end


class MixedAuthenticationSchemeTest < Minitest::Test
  def test_ignores_basic_token68_before_digest
    challenges = Digestory::Challenge.parse_all(
      'Basic abc123, Digest realm="good", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert_equal ["good"], challenges.map(&:realm)
  end
end


class ChallengeProtectionSpaceTest < Minitest::Test
  def test_matches_path_absolute_domain_prefix
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="/private /api/v1", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert challenge.protects?("/private/report", base_uri: "https://example.org")
    assert challenge.protects?("/api/v1/items", base_uri: "https://example.org")
    refute challenge.protects?("/public")
  end

  def test_matches_absolute_domain_prefix
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="https://example.org/private", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert challenge.protects?(
      "https://example.org/private/report"
    )
    refute challenge.protects?(
      "https://example.org/public"
    )
    refute challenge.protects?(
      "https://other.example.org/private/report"
    )
  end

  def test_resolves_relative_target_against_base_uri
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="https://example.org/private", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert challenge.protects?("/private/report", base_uri: "https://example.org")
  end

  def test_rejects_relative_target_without_an_origin_for_enforcement
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="/private", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    refute challenge.protects?("/private/report")
  end

  def test_accepts_absolute_target_for_relative_domain
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="/private", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert challenge.protects?("https://example.org/private/report")
  end
end


class ChallengeDiagnosticsTest < Minitest::Test
  def test_parse_surfaces_unsupported_algorithm_when_no_digest_challenge_is_usable
    assert_raises(Digestory::UnsupportedAlgorithm) do
      Digestory::Challenge.parse(
        'Digest realm="r", nonce="n", algorithm=SHA-1, qop="auth"'
      )
    end
  end
end


class ChallengeQopParsingTest < Minitest::Test
  def test_accepts_common_qop_spacing_variants
    [
      "auth,auth-int",
      "auth, auth-int",
      "auth , auth-int"
    ].each do |raw|
      challenge = Digestory::Challenge.parse(
        "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256, qop=\"#{raw}\""
      )
      assert_includes challenge.qop, "auth"
      assert_includes challenge.qop, "auth-int"
    end
  end
end


class ChallengeDomainParsingTest < Minitest::Test
  def test_domain_uri_can_contain_a_comma
    challenge = Digestory::Challenge.parse(
      'Digest realm="r", domain="/private?next=a,b /other", nonce="n", algorithm=SHA-256, qop="auth"'
    )
    assert_equal ["/private?next=a,b", "/other"], challenge.domain_uris
  end
end
