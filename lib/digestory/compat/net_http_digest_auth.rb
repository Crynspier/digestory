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

      def initialize(_ignored = :ignored)
        @nonce_count = 0
        @mutex = Mutex.new
        @sessions = {}
      end

      def make_cnonce
        Digest::MD5.hexdigest([
          Time.now.to_i,
          Process.pid,
          SecureRandom.random_number(2**32)
        ].join(":"))
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
          header = header.sub("qop=#{effective_qop}", 'qop="' + effective_qop + '"')
        end
        header
      end

      private

      def session_for(uri, username, password, use_username_star:)
        key = [uri.scheme&.downcase, uri.host&.downcase, uri.port, username, password].freeze
        @mutex.synchronize do
          @sessions[key] ||= Digestory::Session.new(
            username: username,
            password: password,
            qop_preference: %w[auth],
            prefer_stronger_algorithm: false,
            allow_legacy_no_qop: true,
            use_username_star: use_username_star
          )
        end
      end

    end
  end
end
