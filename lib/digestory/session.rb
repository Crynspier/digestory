# frozen_string_literal: true

require "securerandom"
require "uri"
require "cgi"

module Digestory
  class Session
    DEFAULT_QOP_PREFERENCE = %w[auth auth-int].freeze

    attr_reader :username, :nonce_count

    def initialize(username:, password:, qop_preference: DEFAULT_QOP_PREFERENCE, prefer_stronger_algorithm: true,
                   allow_legacy_no_qop: false, use_username_star: false)
      @username = username.to_s
      @password = password.to_s
      @qop_preference = qop_preference.map { |q| q.to_s.downcase }.freeze
      @prefer_stronger_algorithm = prefer_stronger_algorithm
      @allow_legacy_no_qop = allow_legacy_no_qop
      @use_username_star = use_username_star
      @mutex = Mutex.new
      @nonce_count = 0
      @current_nonce = nil
      @last = nil
    end

    def authorize(challenge:, method:, uri:, entity_body: nil, qop: nil, cnonce: nil)
      challenges = case challenge
                   when String
                     Challenge.parse_all(challenge)
                   when Array
                     challenge.flat_map { |item| item.is_a?(Challenge) ? [item] : Challenge.parse_all(item.to_s) }
                   when Challenge
                     [challenge]
                   else
                     raise InvalidChallenge, "challenge must be a String, Challenge, or Array"
                   end

      selected_challenge = select_challenge(
        challenges,
        qop: qop,
        entity_body: entity_body
      )

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
          if @current_nonce != selected_challenge.nonce
            @current_nonce = selected_challenge.nonce
            @nonce_count = 0
          end
          raise AuthenticationFailure, "nonce-count exhausted; server must issue a new nonce" if @nonce_count >= 0xffff_ffff

          @nonce_count += 1
          nc = format("%08x", @nonce_count)
          generated_cnonce = cnonce || SecureRandom.base64(32)
        end
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

      username_for_header = selected_challenge.charset == :utf_8 ? @username.unicode_normalize(:nfc) : @username

      username_value = if selected_challenge.userhash
                         Digest.userhash(
                           username: @username,
                           realm: selected_challenge.realm,
                           algorithm: selected_challenge.algorithm.sub(/-sess\\z/i, ""),
                           charset: selected_challenge.charset
                         )
                       else
                         username_for_header
                       end

      params = []
      params << (if @use_username_star && !selected_challenge.userhash && !ascii_only?(@username)
                   ["username*", rfc5987(username_for_header)]
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

      if verify
        raise AuthenticationFailure, "no prior authenticated request" unless state
        raise AuthenticationFailure, "missing rspauth" unless info.rspauth

        if state[:qop]
          unless info.qop == state[:qop] && info.cnonce == state[:cnonce] && info.nc == state[:nc]
            raise AuthenticationFailure, "Authentication-Info request parameters mismatch"
          end
        elsif info.qop
          raise AuthenticationFailure, "unexpected Authentication-Info qop"
        end

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
        expected_size = Algorithm.digest_size(state[:challenge].algorithm) * 2
        unless info.rspauth.bytesize == expected_size
          raise AuthenticationFailure, "Authentication-Info rspauth has the wrong digest length"
        end
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

    def select_challenge(challenges, qop:, entity_body:)
      raise InvalidChallenge, "no Digest challenge found" if challenges.empty?

      usable = challenges.select do |item|
        begin
          requested_qop = qop&.to_s&.downcase
          chosen_qop = requested_qop || item.choose_qop(
            preference: @qop_preference,
            allow_legacy_no_qop: @allow_legacy_no_qop
          )
          next false if requested_qop && !item.supports_qop?(requested_qop)
          next false if chosen_qop == "auth-int" && entity_body.nil?
          true
        rescue UnsupportedQop
          false
        end
      end

      raise UnsupportedQop, "no Digest challenge supports the requested qop and policy" if usable.empty?
      return usable.first unless @prefer_stronger_algorithm

      usable.max_by { |item| Algorithm.secure_rank(item.algorithm) }
    end

    def request_uri(uri)
      return uri.request_uri if uri.is_a?(URI)

      value = uri.to_s
      return value if value == "*" || value.start_with?("/")

      parsed = URI.parse(value)
      return value if parsed.absolute?

      "/#{value}"
    rescue URI::InvalidURIError
      "/#{value}"
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
