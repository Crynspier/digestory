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
