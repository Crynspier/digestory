# frozen_string_literal: true

module Digestory
  class Challenge
    attr_reader :realm, :domain, :nonce, :opaque, :algorithm, :qop,
                :charset, :userhash, :stale, :params

    def self.parse(header)
      challenges = parse_all(header)
      raise InvalidChallenge, "no Digest challenge found" if challenges.empty?
      challenges.first
    end

    def self.parse_all(header)
      raise InvalidChallenge, "missing authentication challenge" if header.nil? || header.strip.empty?

      chunks = Parameters.split_top_level(header)
      challenges = []
      current = nil
      current_scheme = nil

      flush = lambda do
        if current_scheme&.casecmp?("Digest")
          begin
            challenges << new(current)
          rescue UnsupportedAlgorithm
            # RFC 7616 permits clients to ignore Digest challenges that use
            # algorithms they do not understand and continue negotiation.
          end
        end
      end

      chunks.each do |chunk|
        stripped = chunk.strip
        if stripped.match?(/A[A-Za-z][A-Za-z0-9!#$%&'*+.^_|~-]*s+./)
          flush.call if current
          scheme, rest = stripped.split(/s+/, 2)
          current_scheme = scheme
          begin
            current = Parameters.parse_parameter_list(rest.to_s)
          rescue ParseError => e
            raise InvalidChallenge, e.message
          end
          next
        end

        raise InvalidChallenge, "parameter found before authentication scheme" unless current
        key, value = Parameters.split_assignment(stripped)
        canonical = key.downcase
        raise ParseError, "duplicate parameter #{key}" if current.key?(canonical)
        current[canonical] = value
      end

      flush.call if current
      challenges
    rescue ParseError => e
      raise InvalidChallenge, e.message
    end

    def initialize(params)
      @params = params.transform_keys(&:to_s).freeze
      @realm = fetch_required("realm")
      @nonce = fetch_required("nonce")
      @domain = params["domain"]
      @opaque = params["opaque"]
      @algorithm = Algorithm.normalize(params["algorithm"])
      @qop = parse_qop(params["qop"])
      @charset = parse_charset(params["charset"])
      @userhash = parse_bool(params["userhash"], false)
      @stale = parse_bool(params["stale"], false)
      freeze
    end

    def stale?
      @stale
    end

    def supports_qop?(value)
      @qop.include?(value.to_s.downcase)
    end

    def choose_qop(preference: %w[auth auth-int], allow_legacy_no_qop: false)
      preference.each do |wanted|
        normalized = wanted.to_s.downcase
        return normalized if @qop.include?(normalized)
      end

      return nil if @qop.empty? && allow_legacy_no_qop
      raise UnsupportedQop, "server offered no supported qop"
    end

    def with_nonce(value)
      Challenge.new(@params.merge("nonce" => value))
    end

    private

    def fetch_required(key)
      value = @params[key]
      raise InvalidChallenge, "missing #{key}" if value.nil? || value.empty?
      value
    end

    def parse_qop(value)
      return [] if value.nil?
      Parameters.parse_list(value).map(&:downcase).uniq
    end

    def parse_charset(value)
      return :iso_8859_1 if value.nil?
      return :utf_8 if value.casecmp?("UTF-8")
      raise InvalidChallenge, "unsupported charset #{value.inspect}"
    end

    def parse_bool(value, default)
      return default if value.nil?
      case value.downcase
      when "true" then true
      when "false" then false
      else raise InvalidChallenge, "invalid boolean #{value.inspect}"
      end
    end
  end
end
