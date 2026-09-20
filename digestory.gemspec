# frozen_string_literal: true

require_relative "lib/digestory/version"

Gem::Specification.new do |spec|
  spec.name = "digestory"
  spec.version = Digestory::VERSION
  spec.authors = ["Crynspier"]
  spec.email = []
  spec.summary = "Modern HTTP Digest Authentication for Ruby"
  spec.description = "A small, compatibility-aware implementation of RFC 7616 HTTP Digest Authentication for modern Ruby."
  spec.homepage = "https://github.com/Crynspier/digestory"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.files = Dir["LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md", "digestory.gemspec", "Rakefile", "lib/**/*", "test/**/*", ".github/workflows/*"]
  spec.require_paths = ["lib"]
  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "https://github.com/Crynspier/digestory/tree/main",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "documentation_uri" => "#{spec.homepage}#readme",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }
end
