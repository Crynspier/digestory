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

    def nonce
      @challenge.nonce
    end
  end
end
