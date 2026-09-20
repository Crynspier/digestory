# frozen_string_literal: true

require "securerandom"
require "uri"
require "cgi"

module Digestory
  class Session
    DEFAULT_QOP_PREFERENCE = %w[auth auth-int].freeze

    attr_reader :username, :nonce_count

    def initialize(username:, password:, qop_preference: DEFAULT_QOP_PREFERENCE, prefer_stronger_algorithm: true,
                   allow_legacy_no_qop: true, use_username_star: false)
      @username = username.to_s
      @password = password.to_s
      @qop_preference = qop_preference.map { |q| q.to_s.downcase }.freeze
      @prefer_stronger_algorithm = prefer_stronger_algorithm
      @allow_legacy_no_qop = allow_legacy_no_qop
      @use_username_star = use_username_star
      @mutex = Mutex.new
      @nonce_count = 0
      @last = nil
    end

    def authorize(challenge:, method:, uri:, entity_body: nil, qop: nil, cnonce: nil)
      challenge = if challenge.is_a?(String)
                    parsed = Challenge.parse_all(challenge)
                    select_challenge(parsed)
                  elsif challenge.is_a?(Array)
                    select_challenge(challenge)
                  else
                    challenge
                  end
      selected_challenge = challenge
      previous_nonce = @mutex.synchronize { @last && @last[:challenge]&.nonce }
      pending_nonce = @mutex.synchronize { @next_nonce }
      if pending_nonce && previous_nonce == selected_challenge.nonce
        selected_challenge = selected_challenge.with_nonce(pending_nonce)
      end

      qop_value = qop&.to_s&.downcase || selected_challenge.choose_qop(
        preference: @qop_preference,
        allow_legacy_no_qop: @allow_legacy_no_qop
      )

      if qop_value && !selected_challenge.supports_qop?(qop_value)
        raise UnsupportedQop, "qop #{qop_value.inspect} was not offered by the server"
      end
      if qop_value == "auth-int" && entity_body.nil?
        raise UnsupportedQop, "auth-int requires an entity body"
      end

      generated_cnonce = nil
      nc = nil
      @mutex.synchronize do
        if qop_value || Algorithm.sess?(selected_challenge.algorithm)
          @nonce_count += 1
          nc = format("%08x", @nonce_count)
          generated_cnonce = cnonce || SecureRandom.base64(32)
        end
      end

      if Algorithm.sess?(selected_challenge.algorithm) && generated_cnonce.nil?
        raise InvalidChallenge, "session algorithm requires cnonce"
      end

      response = Digest.response(
        challenge: selected_challenge,
        username: @username,
        password: @password,
        method: method.to_s,
        uri: request_uri(uri),
        nc: nc,
        cnonce: generated_cnonce,
        qop: qop_value,
        entity_body: entity_body
      )

      username_value = if selected_challenge.userhash
                         Digest.userhash(
                           username: @username,
                           realm: selected_challenge.realm,
                           algorithm: selected_challenge.algorithm.sub(/-sess\z/i, ""),
                           charset: selected_challenge.charset
                         )
                       else
                         @username
                       end

      params = []
      params << (if @use_username_star && !selected_challenge.userhash && !ascii_only?(@username)
                   ["username*", rfc5987(@username)]
                 else
                   ["username", username_value]
                 end)
      params << ["realm", selected_challenge.realm]
      params << ["uri", request_uri(uri)]
      params << ["algorithm", selected_challenge.algorithm]
      params << ["nonce", selected_challenge.nonce]
      params << ["nc", nc] if nc
      params << ["cnonce", generated_cnonce] if generated_cnonce
      params << ["qop", qop_value] if qop_value
      params << ["response", response]
      params << ["opaque", selected_challenge.opaque] if selected_challenge.opaque
      params << ["userhash", "true"] if selected_challenge.userhash

      header = Serializer.authorization(params)
      @mutex.synchronize do
        @next_nonce = nil
        @last = {
          challenge: selected_challenge,
          request_uri: request_uri(uri),
          method: method.to_s,
          qop: qop_value,
          cnonce: generated_cnonce,
          nc: nc,
          username: @username,
          response: response
        }.freeze
      end
      header
    end

    def update_authentication_info(header, response_body: nil, verify: false)
      info = AuthenticationInfo.parse(header)
      state = @mutex.synchronize { @last }
      if verify && info.rspauth
        raise AuthenticationFailure, "no prior authenticated request" unless state
        expected = Digest.rspauth(
          challenge: state[:challenge],
          username: state[:username],
          password: @password,
          request_uri: state[:request_uri],
          nc: state[:nc],
          cnonce: state[:cnonce],
          qop: state[:qop],
          response_body: response_body
        )
        unless secure_compare(expected, info.rspauth)
          raise AuthenticationFailure, "Authentication-Info rspauth mismatch"
        end
      end
      if info.nextnonce
        @mutex.synchronize do
          @next_nonce = info.nextnonce
        end
      end
      info
    end

    def next_nonce
      @mutex.synchronize { @next_nonce }
    end

    private

    def select_challenge(challenges)
      raise InvalidChallenge, "no Digest challenge found" if challenges.empty?
      return challenges.first unless @prefer_stronger_algorithm

      challenges.max_by { |item| Algorithm.secure_rank(item.algorithm) }
    end

    def request_uri(uri)
      value = uri.is_a?(URI) ? uri.request_uri : uri.to_s
      value = "/#{value}" unless value.start_with?("/")
      value
    end

    def ascii_only?(value)
      value.ascii_only?
    end

    def rfc5987(value)
      bytes = value.encode(Encoding::UTF_8).bytes
      encoded = bytes.map do |byte|
        if (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) ||
           (byte >= 0x30 && byte <= 0x39) || %w[- . _ ~].include?(byte.chr)
          byte.chr
        else
          format("%%%02X", byte)
        end
      end.join
      "UTF-8''#{encoded}"
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      result = 0
      a.bytes.zip(b.bytes) { |x, y| result |= (x ^ y) }
      result.zero?
    end
  end
end
