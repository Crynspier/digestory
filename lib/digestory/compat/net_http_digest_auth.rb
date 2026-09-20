# frozen_string_literal: true

require "cgi"
require "net/http"
require "uri"
require "digestory"

module Net
  class HTTP
    class DigestAuth
      Error = Digestory::Error
      VERSION = Digestory::VERSION

      def initialize(_ignored = :ignored)
        @nonce_count = -1
        @mutex = Mutex.new
      end

      def auth_header(uri, www_authenticate, method, iis = false)
        parsed_uri = uri.is_a?(URI) ? uri : URI.parse(uri.to_s)
        username = CGI.unescape(parsed_uri.user.to_s)
        password = CGI.unescape(parsed_uri.password.to_s)
        raise Digestory::MissingCredential, "URI must contain username and password" if username.empty? && parsed_uri.user.nil?

        challenge = Digestory::Challenge.parse(www_authenticate)
        qop = challenge.choose_qop(preference: %w[auth], allow_legacy_no_qop: true)
        nonce_count, cnonce = @mutex.synchronize do
          if qop || Digestory::Algorithm.sess?(challenge.algorithm)
            @nonce_count += 1
            [format("%08x", @nonce_count), SecureRandom.base64(32)]
          else
            [nil, nil]
          end
        end

        response = Digestory::Digest.response(
          challenge: challenge,
          username: username,
          password: password,
          method: method.to_s,
          uri: parsed_uri.request_uri,
          nc: nonce_count,
          cnonce: cnonce,
          qop: qop,
          entity_body: nil
        )

        params = [
          ["username", username],
          ["realm", challenge.realm],
          ["algorithm", challenge.algorithm],
          ["uri", parsed_uri.request_uri],
          ["nonce", challenge.nonce],
        ]
        if qop || Digestory::Algorithm.sess?(challenge.algorithm)
          params << ["nc", nonce_count]
          params << ["cnonce", cnonce]
        end
        params << ["qop", qop] if qop
        params << ["response", response]
        params << ["opaque", challenge.opaque] if challenge.opaque

        header = Digestory::Serializer.authorization(params)
        if iis && qop
          header = header.sub("qop=#{qop}", 'qop="' + qop + '"')
        end
        header
      end
    end
  end
end
