# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new do |t|
  t.libs << "lib"
  t.pattern = "test/**/*_test.rb"
  t.verbose = true
end

task default: :test


desc "Build and validate the gem"
task :package do
  sh "gem build digestory.gemspec"
  gem = Dir["digestory-*.gem"].max_by { |path| File.mtime(path) }
  sh "gem check #{gem}"
end
