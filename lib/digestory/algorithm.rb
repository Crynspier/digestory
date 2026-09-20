# frozen_string_literal: true

require "digest"
require "openssl"

module Digestory
  module Algorithm
    module_function

    SPECS = {
      "MD5" => { canonical: "MD5", openssl: "MD5", size: 16 },
      "MD5-SESS" => { canonical: "MD5-sess", openssl: "MD5", size: 16 },
      "SHA-256" => { canonical: "SHA-256", openssl: "SHA256", size: 32 },
      "SHA-256-SESS" => { canonical: "SHA-256-sess", openssl: "SHA256", size: 32 },
      "SHA-512-256" => { canonical: "SHA-512-256", openssl: "SHA512", size: 32 },
      "SHA-512-256-SESS" => { canonical: "SHA-512-256-sess", openssl: "SHA512", size: 32 }
    }.freeze

    def normalize(name)
      value = (name || "MD5").to_s.strip
      spec = SPECS[value.upcase]
      raise UnsupportedAlgorithm, "unsupported digest algorithm #{value.inspect}" unless spec

      spec[:canonical]
    end

    def sess?(name)
      normalize(name).end_with?("-sess")
    end

    def digest(name, data)
      normalized = normalize(name)
      spec = SPECS.fetch(normalized.upcase)
      digest = OpenSSL::Digest.new(spec[:openssl]).hexdigest(data)
      normalized.start_with?("SHA-512-256") ? digest[0, 64] : digest
    end

    def digest_size(name)
      SPECS.fetch(normalize(name).upcase)[:size]
    end

    def secure_rank(name)
      case normalize(name)
      when "SHA-256", "SHA-256-sess" then 3
      when "SHA-512-256", "SHA-512-256-sess" then 4
      when "MD5", "MD5-sess" then 1
      else 0
      end
    end
  end
end
