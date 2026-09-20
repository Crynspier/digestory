# frozen_string_literal: true

module Digestory
  module Parameters
    module_function

    def split_top_level(input)
      parts = []
      start = 0
      quoted = false
      escaped = false
      input.each_char.with_index do |char, index|
        if escaped
          escaped = false
        elsif quoted && char == "\\"
          escaped = true
        elsif char == '"'
          quoted = !quoted
        elsif !quoted && char == ','
          parts << input[start...index].strip
          start = index + 1
        end
      end
      raise ParseError, "unterminated quoted string" if quoted || escaped

      parts << input[start..].to_s.strip
      parts.reject(&:empty?)
    end

    def parse_list(input)
      values = []
      split_top_level(input).each do |piece|
        values.concat(piece.split(/\s+/).reject(&:empty?))
      end
      values
    end

    def parse_parameter_list(input)
      params = {}
      split_top_level(input).each do |piece|
        key, value = split_assignment(piece)
        canonical = key.downcase
        raise ParseError, "duplicate parameter #{key}" if params.key?(canonical)

        params[canonical] = value
      end
      params
    end

    def split_assignment(piece)
      index = piece.index('=')
      raise ParseError, "expected parameter assignment: #{piece.inspect}" unless index

      key = piece[0...index].strip
      raise ParseError, "invalid parameter name" unless valid_token?(key)

      raw = piece[(index + 1)..].to_s.strip
      raise ParseError, "missing parameter value for #{key}" if raw.empty?

      [key, parse_value(raw)]
    end

    def parse_value(raw)
      if raw.start_with?('"')
        parse_quoted(raw)
      else
        raise ParseError, "invalid trailing data in parameter" if raw.include?('"')
        raise ParseError, "invalid token value #{raw.inspect}" unless valid_token?(raw)
        raw
      end
    end

    def parse_quoted(raw)
      raise ParseError, "unterminated quoted string" unless raw.end_with?('"')

      out = +""
      escaped = false
      raw[1...-1].each_byte do |byte|
        char = byte.chr
        if escaped
          raise ParseError, "invalid escape sequence" if byte < 0x20 || byte == 0x7f
          out << char
          escaped = false
        elsif byte == 0x5c
          escaped = true
        else
          raise ParseError, "invalid control character" if byte < 0x20 || byte == 0x7f
          out << char
        end
      end
      raise ParseError, "unterminated quoted string" if escaped

      out
    end

    def quoted?(raw)
      raw.is_a?(String) && raw.start_with?('"')
    end

    def valid_token?(value)
      !value.empty? && value.each_byte.all? { |byte| token_byte?(byte) }
    end

    def token_byte?(byte)
      (byte >= 0x30 && byte <= 0x39) ||
        (byte >= 0x41 && byte <= 0x5a) ||
        (byte >= 0x61 && byte <= 0x7a) ||
        "!#$%&'*+-.^_|~".include?(byte.chr) || byte == 0x60
    end

    def quote(value)
      value = value.to_s
      raise InvalidHeader, "header value contains control characters" if value.each_byte.any? { |b| b < 0x20 || b == 0x7f }

      '"' + value.gsub(/(["\\])/) { |m| "\\#{m}" } + '"'
    end
  end
end
