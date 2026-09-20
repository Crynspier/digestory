# frozen_string_literal: true

module Digestory
  module Digest
    module_function

    def response(challenge:, username:, password:, method:, uri:, nc:, cnonce:, qop:, entity_body: nil)
      algorithm = challenge.algorithm
      validate_qop_inputs(qop: qop, nc: nc, cnonce: cnonce, algorithm: algorithm)
      ha1 = ha1(
        algorithm: algorithm,
        username: username,
        realm: challenge.realm,
        password: password,
        nonce: challenge.nonce,
        cnonce: cnonce,
        charset: challenge.charset
      )
      ha2 = ha2(
        algorithm: algorithm,
        method: method,
        uri: uri,
        qop: qop,
        entity_body: entity_body
      )

      kd(algorithm, ha1, if qop
                           "#{challenge.nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}"
                         else
                           "#{challenge.nonce}:#{ha2}"
                         end)
    end

    def rspauth(challenge:, username:, password:, request_uri:, nc:, cnonce:, qop:, response_body: nil)
      algorithm = challenge.algorithm
      validate_qop_inputs(qop: qop, nc: nc, cnonce: cnonce)
      ha1 = ha1(
        algorithm: algorithm,
        username: username,
        realm: challenge.realm,
        password: password,
        nonce: challenge.nonce,
        cnonce: cnonce,
        charset: challenge.charset
      )
      a2 = ":#{request_uri}"
      if qop == "auth-int"
        body_digest = hash(algorithm, body_bytes(response_body))
        a2 = "#{a2}:#{body_digest}"
      end
      ha2 = hash(algorithm, a2)
      kd(algorithm, ha1, if qop
                           "#{challenge.nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}"
                         else
                           "#{challenge.nonce}:#{ha2}"
                         end)
    end

    def userhash(username:, realm:, algorithm:, charset:)
      username_bytes = encode_credential(username, charset)
      realm_bytes = realm.encode(Encoding::BINARY)
      hash(algorithm, username_bytes + ":".b + realm_bytes)
    end

    def ha1(algorithm:, username:, realm:, password:, nonce:, cnonce:, charset:)
      username_bytes = encode_credential(username, charset)
      password_bytes = encode_credential(password, charset)
      realm_bytes = realm.encode(Encoding::BINARY)
      credentials = username_bytes + ":".b + realm_bytes + ":".b + password_bytes
      base = hash(algorithm, credentials)
      if Algorithm.sess?(algorithm)
        hash(algorithm, "#{base}:#{nonce}:#{cnonce}")
      else
        base
      end
    end

    def ha2(algorithm:, method:, uri:, qop:, entity_body:)
      value = "#{method}:#{uri}"
      if qop == "auth-int"
        value = "#{value}:#{hash(algorithm, body_bytes(entity_body))}"
      end
      hash(algorithm, value)
    end

    def kd(algorithm, secret, data)
      hash(algorithm, "#{secret}:#{data}")
    end

    def hash(algorithm, data)
      Algorithm.digest(algorithm, data)
    end

    def encode_credential(value, charset)
      case charset
      when :utf_8
        value.unicode_normalize(:nfc).encode(Encoding::UTF_8).dup.force_encoding(Encoding::BINARY)
      when :iso_8859_1
        value.encode(Encoding::ISO_8859_1).dup.force_encoding(Encoding::BINARY)
      else
        raise InvalidChallenge, "unsupported character set #{charset.inspect}"
      end
    rescue EncodingError => e
      raise InvalidHeader, "credentials cannot be represented in #{charset}: #{e.message}"
    end

    def encode(value, charset)
      case charset
      when :utf_8
        value.encode(Encoding::UTF_8).dup.force_encoding(Encoding::BINARY)
      when :iso_8859_1
        value.encode(Encoding::ISO_8859_1).dup.force_encoding(Encoding::BINARY)
      else
        raise InvalidChallenge, "unsupported character set #{charset.inspect}"
      end
    rescue EncodingError => e
      raise InvalidHeader, "value cannot be represented in #{charset}: #{e.message}"
    end

    def validate_qop_inputs(qop:, nc:, cnonce:)
      if qop
        raise InvalidHeader, "qop requires nonce-count" unless nc&.match?(/\A[0-9a-fA-F]{8}\z/)
        raise InvalidHeader, "qop requires cnonce" if cnonce.nil? || cnonce.empty?
        unless cnonce && cnonce.each_byte.all? { |byte| byte >= 0x20 && byte <= 0x7e }
          raise InvalidHeader, "cnonce must contain only visible ASCII characters"
        end
        raise UnsupportedQop, "unsupported qop #{qop.inspect}" unless %w[auth auth-int].include?(qop)
      end
    end

    def body_bytes(body)
      case body
      when nil
        "".b
      when String
        body.b
      else
        unless body.respond_to?(:read)
          raise InvalidEntityBody, "entity body must be a String or readable IO"
        end
        original_position = body.pos if body.respond_to?(:pos)
        data = body.read
        raise InvalidEntityBody, "entity body IO returned nil" if data.nil?
        if original_position && body.respond_to?(:seek)
          body.seek(original_position)
        elsif body.respond_to?(:rewind) && original_position == 0
          body.rewind
        end
        data.b
      end
    end
  end
end
