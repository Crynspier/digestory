# frozen_string_literal: true

require_relative "../test_helper"

class HeaderSecurityTest < Minitest::Test
  def test_rejects_control_characters_in_quoted_values
    assert_raises(Digestory::InvalidHeader) { Digestory::Parameters.quote("a\n b") }
  end

  def test_rejects_duplicate_challenge_parameters
    assert_raises(Digestory::InvalidChallenge) do
      Digestory::Challenge.parse('Digest realm="r", realm="x", nonce="n"')
    end
  end

  def test_rejects_unknown_algorithm
    assert_raises(Digestory::InvalidChallenge) do
      Digestory::Challenge.parse('Digest realm="r", nonce="n", algorithm=SHA-1')
    end
  end

  def test_authentication_info_nonce_count_is_fixed_width
    assert_raises(Digestory::InvalidAuthenticationInfo) do
      Digestory::AuthenticationInfo.parse('nc=1')
    end
  end
end


class AuthenticationInfoSecurityTest < Minitest::Test
  def test_rejects_non_hex_rspauth
    assert_raises(Digestory::InvalidAuthenticationInfo) do
      Digestory::AuthenticationInfo.parse('rspauth="not-a-digest!"')
    end
  end
end


class AuthenticationInfoContextTest < Minitest::Test
  def test_rejects_qop_without_request_context
    assert_raises(Digestory::InvalidAuthenticationInfo) do
      Digestory::AuthenticationInfo.parse('qop=auth')
    end
  end

  def test_rejects_request_context_without_qop
    assert_raises(Digestory::InvalidAuthenticationInfo) do
      Digestory::AuthenticationInfo.parse('cnonce="c", nc=00000001')
    end
  end
end
