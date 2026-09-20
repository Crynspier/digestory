# frozen_string_literal: true

require_relative "test_helper"

class FuzzSmokeTest < Minitest::Test
  def test_parser_survives_deterministic_malformed_corpus
    seed = 0xD16570
    500.times do |i|
      rng = Random.new(seed + i)
      candidate = Array.new(rng.rand(0..160)) { rng.rand(0..255).chr }.join
      begin
        Digestory::Challenge.parse(candidate)
      rescue Digestory::Error, ArgumentError, EncodingError
        # Expected for malformed data.
      end
    end
  end
end
