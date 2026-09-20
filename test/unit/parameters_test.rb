# frozen_string_literal: true

require_relative "../test_helper"

class ParametersTest < Minitest::Test
  def test_split_top_level_respects_quotes
    assert_equal ["a=\"x,y\"", "b=c"], Digestory::Parameters.split_top_level('a="x,y", b=c')
  end

  def test_parse_parameter_list_unescapes_quotes
    assert_equal({ "realm" => 'a"b', "qop" => "auth,auth-int" }, Digestory::Parameters.parse_parameter_list('realm="a\\"b", qop="auth,auth-int"'))
  end

  def test_reject_duplicate_parameters
    assert_raises(Digestory::ParseError) do
      Digestory::Parameters.parse_parameter_list('realm="one", realm="two"')
    end
  end

  def test_reject_unterminated_quote
    assert_raises(Digestory::ParseError) { Digestory::Parameters.parse_parameter_list('realm="one') }
  end
end
