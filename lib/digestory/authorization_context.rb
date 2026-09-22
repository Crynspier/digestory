# frozen_string_literal: true

module Digestory
  class AuthorizationContext
    attr_reader :header, :challenge, :request_uri, :method, :qop, :cnonce,
                :nc, :username, :response, :nonce_key, :protection_key

    def initialize(header:, challenge:, request_uri:, method:, qop:, cnonce:, nc:, username:, response:, nonce_key:, protection_key:)
      @header = header
      @challenge = challenge
      @request_uri = request_uri
      @method = method
      @qop = qop
      @cnonce = cnonce
      @nc = nc
      @username = username
      @response = response
      @nonce_key = nonce_key
      @protection_key = protection_key
      freeze
    end

    # Compatibility accessor for the pre-0.1.1 internal state hash shape.
    def [](key)
      case key.to_sym
      when :challenge then @challenge
      when :request_uri then @request_uri
      when :method then @method
      when :qop then @qop
      when :cnonce then @cnonce
      when :nc then @nc
      when :username then @username
      when :response then @response
      when :nonce_key then @nonce_key
      when :protection_key then @protection_key
      else
        nil
      end
    end

    def nonce
      @challenge.nonce
    end
  end
end
