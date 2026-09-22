# frozen_string_literal: true

require "net/http"
require "digest"
require "securerandom"
require "uri"
require "digestory"

module Net
  class HTTP
    class DigestAuth
      Error = Digestory::Error
      VERSION = Digestory::VERSION

      DEFAULT_MAX_SESSIONS = 128

      def initialize(_ignored = :ignored, max_sessions: DEFAULT_MAX_SESSIONS)
        @nonce_count = 0
        @max_sessions = Integer(max_sessions)
        raise ArgumentError, "max_sessions must be positive" if @max_sessions <= 0

        @cache_salt = SecureRandom.random_bytes(32)
        @mutex = Mutex.new
        @sessions = {}
      end

      def make_cnonce
        SecureRandom.hex(16)
      end

      # Historical helper retained for compatibility. The authentication
      # implementation itself now uses Digestory::Session's per-nonce state.
      def next_nonce
        @mutex.synchronize do
          @nonce_count += 1
        end
      end

      def auth_header(uri, www_authenticate, method, iis = false, entity_body: nil, entity_digest: nil,
                      qop: nil, use_username_star: false)
        parsed_uri = uri.is_a?(URI) ? uri : URI.parse(uri.to_s)
        username = URI::DEFAULT_PARSER.unescape(parsed_uri.user.to_s)
        password = URI::DEFAULT_PARSER.unescape(parsed_uri.password.to_s)
        raise Digestory::MissingCredential, "URI must contain username and password" if parsed_uri.user.nil? || parsed_uri.password.nil?

        challenge = Digestory::Challenge.parse(www_authenticate)
        effective_qop = qop&.to_s&.downcase || (challenge.supports_qop?("auth") ? "auth" : nil)

        session = session_for(parsed_uri, username, password, use_username_star: use_username_star)
        header = session.authorize(
          challenge: www_authenticate,
          method: method.to_s,
          uri: parsed_uri,
          entity_body: entity_body,
          entity_digest: entity_digest,
          qop: effective_qop,
          cnonce: make_cnonce
        )

        if iis && effective_qop
          header = Digestory::Serializer.authorization(
            extract_authorization_params(header),
            quoted: ["qop"]
          )
        end
        header
      end

      private

      def session_for(uri, username, password, use_username_star:)
        key = [
          uri.scheme&.downcase,
          uri.host&.downcase,
          uri.port,
          username,
          credential_fingerprint(password),
          use_username_star
        ].freeze

        @mutex.synchronize do
          unless @sessions.key?(key)
            if @sessions.length >= @max_sessions
              raise Digestory::AuthenticationFailure,
                    "DigestAuth session cache limit reached; create a new DigestAuth instance or increase max_sessions"
            end

            @sessions[key] = Digestory::Session.new(
              username: username,
              password: password,
              qop_preference: %w[auth],
              prefer_stronger_algorithm: false,
              allow_legacy_no_qop: true,
              use_username_star: use_username_star
            )
          end

          @sessions.fetch(key)
        end
      end

      def credential_fingerprint(password)
        Digest::SHA256.hexdigest(@cache_salt + password.to_s.b)
      end

      def extract_authorization_params(header)
        body = header.delete_prefix("Digest ")
        Digestory::Parameters.split_top_level(body).map do |piece|
          Digestory::Parameters.split_assignment(piece)
        end
      end
    end
  end
end
