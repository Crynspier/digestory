# frozen_string_literal: true

module Digestory
  module Serializer
    module_function

    QUOTED = %w[username username* realm nonce uri response cnonce opaque]

    def authorization(params)
      pairs = params.map do |key, value|
        raise InvalidHeader, "nil header value for #{key}" if value.nil?
        if key == "username*"
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
