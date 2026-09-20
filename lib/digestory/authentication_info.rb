# frozen_string_literal: true

module Digestory
  class AuthenticationInfo
    attr_reader :nextnonce, :rspauth, :cnonce, :nc, :qop, :params

    def self.parse(header)
      raise InvalidAuthenticationInfo, "missing Authentication-Info" if header.nil?

      params = Parameters.parse_parameter_list(header)
      new(params)
    rescue ParseError => e
      raise InvalidAuthenticationInfo, e.message
    end

    def initialize(params)
      @params = params.transform_keys(&:to_s).freeze
      @nextnonce = @params["nextnonce"]
      @rspauth = @params["rspauth"]
      @cnonce = @params["cnonce"]
      @nc = @params["nc"]
      @qop = @params["qop"]&.downcase
      validate
      freeze
    end

    def nextnonce?
      !@nextnonce.nil?
    end

    private

    def validate
      if @nc && !@nc.match?(/\A[0-9a-fA-F]{8}\z/)
        raise InvalidAuthenticationInfo, "invalid nonce-count"
      end
      if @qop && !%w[auth auth-int].include?(@qop)
        raise InvalidAuthenticationInfo, "unsupported qop #{@qop.inspect}"
      end
    end
  end
end
