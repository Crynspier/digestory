# frozen_string_literal: true

require "securerandom"
require "uri"

module Digestory
  class Session
    DEFAULT_QOP_PREFERENCE = %w[auth auth-int].freeze
    MAX_NONCE_COUNT = 0xffff_ffff

    attr_reader :username, :nonce_count

    def initialize(username:, password:, qop_preference: DEFAULT_QOP_PREFERENCE, prefer_stronger_algorithm: true,
                   allow_legacy_no_qop: false, use_username_star: false, enforce_domain: false)
      @username = username.to_s
      @password = password.to_s
      raise InvalidHeader, "username cannot contain colon" if @username.include?(":")
      @qop_preference = qop_preference.map { |q| q.to_s.downcase }.freeze
      @prefer_stronger_algorithm = prefer_stronger_algorithm
      @allow_legacy_no_qop = allow_legacy_no_qop
      @use_username_star = use_username_star
      @enforce_domain = enforce_domain
      @mutex = Mutex.new
      @nonce_counts = Hash.new(0)
      @nonce_count = 0
      @next_nonce = nil
      @last = nil
    end

    # Backwards-compatible API. When verify: true is used with concurrent
    # requests, use authorize_with_context instead so each response can be
    # correlated with its own immutable AuthorizationContext.
    def authorize(challenge:, method:, uri:, entity_body: nil, entity_digest: nil, qop: nil, cnonce: nil)
      context = build_authorization(
        challenge: challenge,
        method: method,
        uri: uri,
        entity_body: entity_body,
        entity_digest: entity_digest,
        qop: qop,
        cnonce: cnonce,
        apply_legacy_nextnonce: true
      )
      @mutex.synchronize do
        @next_nonce = nil
        @last = context
      end
      context.header
    end

    # Returns an immutable request-specific context suitable for concurrent
    # authentication exchanges.
    def authorize_with_context(challenge:, method:, uri:, entity_body: nil, entity_digest: nil, qop: nil, cnonce: nil)
      build_authorization(
        challenge: challenge,
        method: method,
        uri: uri,
        entity_body: entity_body,
        entity_digest: entity_digest,
        qop: qop,
        cnonce: cnonce
      )
    end

    # Continues an authentication exchange using an Authentication-Info
    # nextnonce explicitly. This avoids global request correlation state.
    def authorize_from(context, method:, uri:, entity_body: nil, entity_digest: nil, qop: context.qop, cnonce: nil, nonce: nil)
      raise ArgumentError, "context must be a Digestory::AuthorizationContext" unless context.is_a?(AuthorizationContext)

      build_authorization(
        challenge: context.challenge,
        method: method,
        uri: uri,
        entity_body: entity_body,
        entity_digest: entity_digest,
        qop: qop,
        cnonce: cnonce,
        nonce: nonce || context.challenge.nonce
      )
    end

    def update_authentication_info(header, response_body: nil, response_digest: nil, verify: false, context: nil)
      info = AuthenticationInfo.parse(header)
      state = context || @mutex.synchronize { @last }

      verify_authentication_info!(state, info, response_body: response_body, response_digest: response_digest) if verify

      if info.nextnonce && context.nil?
        @mutex.synchronize { @next_nonce = info.nextnonce }
      end
      info
    end

    def verify_authentication_info(context, header, response_body: nil, response_digest: nil)
      raise ArgumentError, "context must be a Digestory::AuthorizationContext" unless context.is_a?(AuthorizationContext)

      update_authentication_info(
        header,
        response_body: response_body,
        response_digest: response_digest,
        verify: true,
        context: context
      )
    end

    # Legacy convenience accessor. New concurrent code should use the
    # AuthenticationInfo returned by verify_authentication_info instead.
    def next_nonce
      @mutex.synchronize { @next_nonce }
    end

    private

    def build_authorization(challenge:, method:, uri:, entity_body:, entity_digest:, qop:, cnonce:, nonce: nil,
                            apply_legacy_nextnonce: false)
      challenges = parse_challenges(challenge)
      selected_challenge = select_challenge(
        challenges,
        qop: qop,
        entity_body: entity_body,
        entity_digest: entity_digest
      )

      if apply_legacy_nextnonce
        pending_nonce, previous_nonce = @mutex.synchronize { [@next_nonce, @last&.nonce] }
        if pending_nonce && previous_nonce == selected_challenge.nonce
          selected_challenge = selected_challenge.with_nonce(pending_nonce)
        end
      elsif nonce
        selected_challenge = selected_challenge.with_nonce(nonce) unless nonce == selected_challenge.nonce
      end

      request_target = request_uri(uri)
      if @enforce_domain && !selected_challenge.protects?(request_target, base_uri: absolute_base_uri(uri))
        raise InvalidChallenge, "request URI is outside the Digest challenge protection space"
      end

      qop_value = qop&.to_s&.downcase || selected_challenge.choose_qop(
        preference: @qop_preference,
        allow_legacy_no_qop: @allow_legacy_no_qop
      )

      if qop_value && !selected_challenge.supports_qop?(qop_value)
        raise UnsupportedQop, "qop #{qop_value.inspect} was not offered by the server"
      end

      generated_cnonce = nil
      nc = nil
      nonce_key = nil

      if qop_value || Algorithm.sess?(selected_challenge.algorithm)
        nonce_key = nonce_state_key(selected_challenge, request_target)
        @mutex.synchronize do
          current = @nonce_counts[nonce_key]
          raise AuthenticationFailure, "nonce-count exhausted; server must issue a new nonce" if current >= MAX_NONCE_COUNT

          current += 1
          @nonce_counts[nonce_key] = current
          @nonce_count = current
          nc = format("%08x", current)
          generated_cnonce = cnonce || SecureRandom.base64(32)
        end
      end

      response = Digest.response(
        challenge: selected_challenge,
        username: @username,
        password: @password,
        method: method.to_s,
        uri: request_target,
        nc: nc,
        cnonce: generated_cnonce,
        qop: qop_value,
        entity_body: entity_body,
        entity_digest: entity_digest
      )

      username_for_header = selected_challenge.charset == :utf_8 ? @username.unicode_normalize(:nfc) : @username

      username_value = if selected_challenge.userhash
                         Digest.userhash(
                           username: @username,
                           realm: selected_challenge.realm,
                           algorithm: selected_challenge.algorithm.sub(/-sess\z/i, ""),
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
      params << ["uri", request_target]
      params << ["algorithm", selected_challenge.algorithm]
      params << ["nonce", selected_challenge.nonce]
      params << ["nc", nc] if nc
      params << ["cnonce", generated_cnonce] if generated_cnonce
      params << ["qop", qop_value] if qop_value
      params << ["response", response]
      params << ["opaque", selected_challenge.opaque] if selected_challenge.opaque
      params << ["userhash", "true"] if selected_challenge.userhash

      AuthorizationContext.new(
        header: Serializer.authorization(params),
        challenge: selected_challenge,
        request_uri: request_target,
        method: method.to_s,
        qop: qop_value,
        cnonce: generated_cnonce,
        nc: nc,
        username: @username,
        response: response,
        nonce_key: nonce_key
      )
    end

    def parse_challenges(challenge)
      case challenge
      when String
        Challenge.parse_all(challenge)
      when Array
        challenge.flat_map { |item| item.is_a?(Challenge) ? [item] : Challenge.parse_all(item.to_s) }
      when Challenge
        [challenge]
      else
        raise InvalidChallenge, "challenge must be a String, Challenge, or Array"
      end
    end

    def select_challenge(challenges, qop:, entity_body:, entity_digest:)
      raise InvalidChallenge, "no Digest challenge found" if challenges.empty?

      usable = challenges.select do |item|
        begin
          requested_qop = qop&.to_s&.downcase
          chosen_qop = requested_qop || item.choose_qop(
            preference: @qop_preference,
            allow_legacy_no_qop: @allow_legacy_no_qop
          )
          next false if requested_qop && !item.supports_qop?(requested_qop)
          next false if chosen_qop == "auth-int" && entity_body.nil? && entity_digest.nil?
          true
        rescue UnsupportedQop
          false
        end
      end

      raise UnsupportedQop, "no Digest challenge supports the requested qop and policy" if usable.empty?
      return usable.first unless @prefer_stronger_algorithm

      usable.max_by { |item| Algorithm.secure_rank(item.algorithm) }
    end

    def verify_authentication_info!(state, info, response_body:, response_digest:)
      raise AuthenticationFailure, "no prior authenticated request" unless state
      raise AuthenticationFailure, "missing rspauth" unless info.rspauth

      if state.qop
        unless info.qop == state.qop && info.cnonce == state.cnonce && info.nc&.downcase == state.nc
          raise AuthenticationFailure, "Authentication-Info request parameters mismatch"
        end
      elsif info.qop
        raise AuthenticationFailure, "unexpected Authentication-Info qop"
      end

      expected = Digest.rspauth(
        challenge: state.challenge,
        username: state.username,
        password: @password,
        request_uri: state.request_uri,
        nc: state.nc,
        cnonce: state.cnonce,
        qop: state.qop,
        response_body: response_body,
        entity_digest: response_digest
      )
      expected_size = Algorithm.digest_size(state.challenge.algorithm) * 2
      unless info.rspauth.bytesize == expected_size
        raise AuthenticationFailure, "Authentication-Info rspauth has the wrong digest length"
      end
      unless secure_compare(expected, info.rspauth.downcase)
        raise AuthenticationFailure, "Authentication-Info rspauth mismatch"
      end
    end

    def nonce_state_key(challenge, request_target)
      origin = begin
        parsed = URI.parse(request_target)
        parsed.absolute? ? [parsed.scheme&.downcase, parsed.host&.downcase, parsed.port] : nil
      rescue URI::InvalidURIError
        nil
      end
      [origin, challenge.realm, challenge.domain, challenge.opaque, challenge.nonce].freeze
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

    def absolute_base_uri(uri)
      return uri if uri.is_a?(URI) && uri.absolute?

      value = uri.to_s
      parsed = URI.parse(value)
      parsed if parsed.absolute?
    rescue URI::InvalidURIError
      nil
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
