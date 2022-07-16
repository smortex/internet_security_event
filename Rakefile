# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'github_changelog_generator/task'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

GitHubChangelogGenerator::RakeTask.new :changelog do |config|
  config.user = 'smortex'
  config.project = 'internet_security_event'
  config.since_tag = 'v1.2.1'
  require 'internet_security_event/version'
  config.future_release = "v#{InternetSecurityEvent::VERSION}"
end

task default: :spec
