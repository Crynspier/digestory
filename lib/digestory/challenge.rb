# frozen_string_literal: true

require "uri"

module Digestory
  class Challenge
    attr_reader :realm, :domain, :nonce, :opaque, :algorithm, :qop,
                :charset, :userhash, :stale, :params

    def self.parse(header)
      challenges = parse_all(header)
      return challenges.first unless challenges.empty?

      if digest_scheme_present?(header)
        raise UnsupportedAlgorithm, "no supported Digest challenge found"
      end

      raise InvalidChallenge, "no Digest challenge found"
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
        if stripped.match?(/\A[A-Za-z][A-Za-z0-9!#$%&'*+.^_|~-]*\s+./)
          flush.call if current
          scheme, rest = stripped.split(/\s+/, 2)
          current_scheme = scheme
          if scheme.casecmp?("Digest")
            begin
              current = Parameters.parse_parameter_list(rest.to_s)
            rescue ParseError => e
              raise InvalidChallenge, e.message
            end
          else
            current = nil
          end
          next
        end

        if current.nil? && current_scheme && !current_scheme.casecmp?("Digest")
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
      @domain_uris = parse_domain(@domain).freeze
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

    def domain_uris
      @domain_uris
    end

    def protection_space_key
      [@realm, @domain, @opaque].freeze
    end

    # Returns true when the supplied target is within this challenge's
    # declared protection space. When domain is absent, RFC 7616 defines the
    # protection space as the web-origin; origin membership cannot be inferred
    # from a relative URI alone, so the method returns true in that case.
    def protects?(uri, base_uri: nil)
      return true if @domain_uris.empty?

      target = resolve_uri_reference(uri, base_uri)
      return false unless target
      return false if relative_reference?(uri) && !absolute_uri?(target)

      @domain_uris.any? { |entry| uri_prefix_match?(entry, target) }
    rescue URI::InvalidURIError
      false
    end

    def with_nonce(value)
      Challenge.new(@params.merge("nonce" => value))
    end

    private

    def self.digest_scheme_present?(header)
      Parameters.split_top_level(header.to_s).any? do |chunk|
        chunk.strip.match?(/\ADigest\s+/i)
      end
    rescue ParseError
      false
    end

    def fetch_required(key)
      value = @params[key]
      raise InvalidChallenge, "missing #{key}" if value.nil? || value.empty?
      value
    end

    def parse_domain(value)
      return [] if value.nil? || value.empty?

      value.split(/\s+/).reject(&:empty?).each do |entry|
        parsed = URI.parse(entry)
        unless parsed.absolute? || entry.start_with?("/")
          raise InvalidChallenge, "invalid domain URI #{entry.inspect}"
        end
      rescue URI::InvalidURIError => e
        raise InvalidChallenge, "invalid domain URI #{entry.inspect}: #{e.message}"
      end
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

    def resolve_uri_reference(value, base_uri)
      return value.to_s if value.to_s == "*"

      uri = URI.parse(value.to_s)
      return uri.to_s if uri.absolute?
      return nil unless base_uri

      base = URI.parse(base_uri.to_s)
      return nil unless base.absolute?

      URI.join(base.to_s.end_with?("/") ? base.to_s : "#{base}/", value.to_s).to_s
    end

    def relative_reference?(value)
      uri = URI.parse(value.to_s)
      !uri.absolute?
    end

    def absolute_uri?(value)
      URI.parse(value.to_s).absolute?
    end

    def uri_prefix_match?(entry, target)
      entry_uri = URI.parse(entry)
      target_uri = URI.parse(target)

      if entry.start_with?("/")
        target_path = target_uri.absolute? ? target_uri.path.to_s : target_uri.to_s
        return target_path.start_with?(entry)
      end

      return false unless target_uri.absolute?
      return false unless entry_uri.scheme&.casecmp?(target_uri.scheme)
      return false unless entry_uri.host&.casecmp?(target_uri.host)
      return false unless effective_port(entry_uri) == effective_port(target_uri)

      entry_target = entry_uri.to_s
      target_target = target_uri.to_s
      target_target.start_with?(entry_target)
    end

    def effective_port(uri)
      return uri.port if uri.port
      case uri.scheme&.downcase
      when "http" then 80
      when "https" then 443
      else nil
      end
    end
  end
end
