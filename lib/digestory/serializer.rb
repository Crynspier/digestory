# frozen_string_literal: true

module Digestory
  module Serializer
    module_function

    QUOTED = %w[username username* realm nonce uri response cnonce opaque]

    def authorization(params)
      pairs = params.map do |key, value|
        raise InvalidHeader, "nil header value for #{key}" if value.nil?
        if key == "username*"
          unless value.ascii_only? && value.each_byte.none? { |byte| byte < 0x20 || byte == 0x7f }
            raise InvalidHeader, "invalid username* header value"
          end
          "username*=#{value}"
        elsif QUOTED.include?(key)
          "#{key}=#{Parameters.quote(value)}"
        else
          raise InvalidHeader, "unsupported Authorization parameter #{key}" unless Parameters.valid_token?(value.to_s)
          "#{key}=#{value}"
        end
      end
      "Digest #{pairs.join(', ')}"
    end
  end
end
