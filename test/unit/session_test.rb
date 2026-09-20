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
