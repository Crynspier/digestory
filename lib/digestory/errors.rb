# frozen_string_literal: true

module Digestory
  class Error < StandardError; end
  class ParseError < Error; end
  class InvalidChallenge < Error; end
  class UnsupportedAlgorithm < InvalidChallenge; end
  class UnsupportedQop < Error; end
  class InvalidAuthenticationInfo < Error; end
  class InvalidHeader < Error; end
  class MissingCredential < Error; end
  class InvalidEntityBody < Error; end
  class AuthenticationFailure < Error; end
end
