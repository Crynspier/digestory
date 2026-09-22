# frozen_string_literal: true

require_relative "../test_helper"

class SessionTest < Minitest::Test
  def test_authorizes_and_increments_nonce_count
    session = Digestory::Session.new(username: "Mufasa", password: "Circle of Life", use_username_star: true)
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n"'
    first = session.authorize(challenge: challenge, method: "GET", uri: "/")
    second = session.authorize(challenge: challenge, method: "GET", uri: "/")
    assert_includes first, "nc=00000001"
    refute_respond_to session, :password
    assert_includes second, "nc=00000002"
  end

  def test_selects_stronger_digest_challenge
    session = Digestory::Session.new(username: "u", password: "p")
    challenge = 'Digest realm="m", qop="auth", algorithm=MD5, nonce="m", Digest realm="s", qop="auth", algorithm=SHA-256, nonce="s"'
    header = session.authorize(challenge: challenge, method: "GET", uri: "/")
    assert_includes header, 'algorithm=SHA-256'
    assert_includes header, 'nonce="s"'
  end

  def test_nonce_count_restarts_when_server_nonce_changes
    session = Digestory::Session.new(username: "u", password: "p")
    first = session.authorize(
      challenge: 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="one"',
      method: "GET",
      uri: "/"
    )
    second = session.authorize(
      challenge: 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="two"',
      method: "GET",
      uri: "/"
    )
    assert_includes first, "nc=00000001"
    assert_includes second, "nc=00000001"
  end

  def test_userhash_authorization
    session = Digestory::Session.new(username: "Jäsøn Doe", password: "Secret")
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n", charset=UTF-8, userhash=true'
    header = session.authorize(challenge: challenge, method: "GET", uri: "/")
    assert_match(/username="[0-9a-f]{64}"/, header)
    assert_includes header, "userhash=true"
  end

  def test_authentication_info_verification_and_nextnonce
    session = Digestory::Session.new(username: "u", password: "p")
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n", charset=UTF-8'
    session.authorize(challenge: challenge, method: "GET", uri: "/")
    state = session.instance_variable_get(:@last)
    rspauth = Digestory::Digest.rspauth(
      challenge: state[:challenge],
      username: "u",
      password: "p",
      request_uri: "/",
      nc: state[:nc],
      cnonce: state[:cnonce],
      qop: "auth"
    )
    info = session.update_authentication_info("qop=auth, rspauth=\"#{rspauth}\", cnonce=\"#{state[:cnonce]}\", nc=#{state[:nc]}, nextnonce=\"n2\"", verify: true)
    assert_equal "n2", info.nextnonce
    assert_equal "n2", session.next_nonce

    header = session.authorize(challenge: challenge, method: "GET", uri: "/next")
    assert_includes header, 'nonce="n2"'
    assert_nil session.next_nonce
  end
end


class SessionHardeningTest < Minitest::Test
  def test_requires_qop_by_default
    session = Digestory::Session.new(username: "u", password: "p")
    assert_raises(Digestory::UnsupportedQop) do
      session.authorize(
        challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256',
        method: "GET",
        uri: "/"
      )
    end
  end

  def test_falls_back_when_stronger_challenge_has_unsupported_qop
    session = Digestory::Session.new(username: "u", password: "p")
    challenge = [
      Digestory::Challenge.parse('Digest realm="strong", nonce="s", algorithm=SHA-256, qop="auth-conf"'),
      Digestory::Challenge.parse('Digest realm="usable", nonce="u", algorithm=MD5, qop="auth"')
    ]
    header = session.authorize(challenge: challenge, method: "GET", uri: "/")
    assert_includes header, 'realm="usable"'
  end

  def test_preserves_absolute_form_request_target_string
    session = Digestory::Session.new(username: "u", password: "p")
    header = session.authorize(
      challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"',
      method: "GET",
      uri: "http://example.org/resource?x=1"
    )
    assert_includes header, 'uri="http://example.org/resource?x=1"'
  end

  def test_verification_rejects_mismatched_authentication_info_context
    session = Digestory::Session.new(username: "u", password: "p")
    session.authorize(
      challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"',
      method: "GET",
      uri: "/"
    )
    assert_raises(Digestory::AuthenticationFailure) do
      session.update_authentication_info('qop=auth, rspauth="' + ("0" * 64) + '", cnonce="wrong", nc=00000001', verify: true)
    end
  end
end


class SessionNonceLimitTest < Minitest::Test
  def test_rejects_nonce_count_overflow
    session = Digestory::Session.new(username: "u", password: "p")
    session.instance_variable_set(:@nonce_count, 0xffff_ffff)
    session.instance_variable_set(:@current_nonce, "n")
    assert_raises(Digestory::AuthenticationFailure) do
      session.authorize(
        challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"',
        method: "GET",
        uri: "/"
      )
    end
  end

  def test_accepts_valid_uppercase_authentication_info_hex
    session = Digestory::Session.new(username: "u", password: "p")
    session.authorize(
      challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"',
      method: "GET",
      uri: "/"
    )
    state = session.instance_variable_get(:@last)
    expected = Digestory::Digest.rspauth(
      challenge: state[:challenge],
      username: "u",
      password: "p",
      request_uri: "/",
      nc: state[:nc],
      cnonce: state[:cnonce],
      qop: "auth"
    ).upcase
    info = 'qop=auth, cnonce="' + state[:cnonce] + '", nc=' + state[:nc].upcase + ', rspauth="' + expected + '"'
    session.update_authentication_info(info, verify: true)
  end

  def test_rejects_wrong_rspauth_length
    session = Digestory::Session.new(username: "u", password: "p")
    session.authorize(
      challenge: 'Digest realm="r", nonce="n", algorithm=SHA-256, qop="auth"',
      method: "GET",
      uri: "/"
    )
    assert_raises(Digestory::AuthenticationFailure) do
      session.update_authentication_info('qop=auth, cnonce="' + session.instance_variable_get(:@last)[:cnonce] + '", nc=00000001, rspauth="00"', verify: true)
    end
  end
end


class SessionCredentialValidationTest < Minitest::Test
  def test_rejects_username_with_colon
    assert_raises(Digestory::InvalidHeader) do
      Digestory::Session.new(username: "u:v", password: "p")
    end
  end
end


class SessionRequestContextTest < Minitest::Test
  def build_rspauth(context, password: "p", response_body: nil)
    Digestory::Digest.rspauth(
      challenge: context.challenge,
      username: context.username,
      password: password,
      request_uri: context.request_uri,
      nc: context.nc,
      cnonce: context.cnonce,
      qop: context.qop,
      response_body: response_body
    )
  end

  def test_request_contexts_verify_out_of_order
    session = Digestory::Session.new(username: "u", password: "p")
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n"'

    first = session.authorize_with_context(challenge: challenge, method: "GET", uri: "/one")
    second = session.authorize_with_context(challenge: challenge, method: "GET", uri: "/two")

    assert_equal "00000001", first.nc
    assert_equal "00000002", second.nc

    second_info = session.verify_authentication_info(
      second,
      'qop=auth, rspauth="' + build_rspauth(second) + '", cnonce="' + second.cnonce + '", nc=' + second.nc
    )
    first_info = session.verify_authentication_info(
      first,
      'qop=auth, rspauth="' + build_rspauth(first) + '", cnonce="' + first.cnonce + '", nc=' + first.nc
    )

    assert_equal second.qop, second_info.qop
    assert_equal first.qop, first_info.qop
  end

  def test_authorize_from_context_uses_explicit_nextnonce
    session = Digestory::Session.new(username: "u", password: "p")
    challenge = 'Digest realm="r", qop="auth", algorithm=SHA-256, nonce="n"'

    first = session.authorize_with_context(challenge: challenge, method: "GET", uri: "/")
    rspauth = build_rspauth(first)
    info = session.verify_authentication_info(
      first,
      'qop=auth, rspauth="' + rspauth + '", cnonce="' + first.cnonce + '", nc=' + first.nc + ', nextnonce="n2"'
    )

    next_context = session.authorize_from(first, method: "GET", uri: "/next", nonce: info.nextnonce)
    assert_equal "n2", next_context.nonce
    assert_equal "00000001", next_context.nc
  end

  def test_auth_int_allows_empty_entity_body
    session = Digestory::Session.new(username: "u", password: "p")
    context = session.authorize_with_context(
      challenge: 'Digest realm="r", qop="auth-int", algorithm=SHA-256, nonce="n"',
      method: "GET",
      uri: "/"
    )

    assert_equal "auth-int", context.qop
    assert_equal "00000001", context.nc
  end
end


class SessionProtectionSpaceTest < Minitest::Test
  def test_optional_domain_enforcement
    session = Digestory::Session.new(username: "u", password: "p", enforce_domain: true)
    assert_raises(Digestory::InvalidChallenge) do
      session.authorize(
        challenge: 'Digest realm="r", domain="/private", nonce="n", algorithm=SHA-256, qop="auth"',
        method: "GET",
        uri: "/public"
      )
    end
  end

  def test_domain_enforcement_accepts_protected_path
    session = Digestory::Session.new(username: "u", password: "p", enforce_domain: true)
    header = session.authorize(
      challenge: 'Digest realm="r", domain="/private", nonce="n", algorithm=SHA-256, qop="auth"',
      method: "GET",
      uri: "/private/report"
    )
    assert_includes header, 'uri="/private/report"'
  end
end


class SessionAuthIntVerificationTest < Minitest::Test
  def test_verifies_auth_int_with_precomputed_response_digest
    session = Digestory::Session.new(username: "u", password: "p")
    context = session.authorize_with_context(
      challenge: 'Digest realm="r", qop="auth-int", algorithm=SHA-256, nonce="n"',
      method: "POST",
      uri: "/",
      entity_body: "request"
    )
    response_body = "response"
    response_digest = Digestory::Algorithm.digest("SHA-256", response_body)
    rspauth = Digestory::Digest.rspauth(
      challenge: context.challenge,
      username: context.username,
      password: "p",
      request_uri: context.request_uri,
      nc: context.nc,
      cnonce: context.cnonce,
      qop: context.qop,
      entity_digest: response_digest
    )
    session.verify_authentication_info(
      context,
      'qop=auth-int, rspauth="' + rspauth + '", cnonce="' + context.cnonce + '", nc=' + context.nc,
      response_digest: response_digest
    )
  end
end
