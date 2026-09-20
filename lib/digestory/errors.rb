# frozen_string_literal: true

module Digestory
  class Error < StandardError; end
  class ParseError < Error; end
  class UnsupportedAlgorithm < Error; end
  class UnsupportedQop < Error; end
  class InvalidChallenge < Error; end
  class InvalidAuthenticationInfo < Error; end
  class InvalidHeader < Error; end
  class MissingCredential < Error; end
  class InvalidEntityBody < Error; end
  class AuthenticationFailure < Error; end
end
