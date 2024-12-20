# frozen_string_literal: true

require 'bundler/setup'

begin
  require 'rake/testtask'
  Rake::TestTask.new do |t|
    t.libs.push 'lib'
    t.test_files = FileList['test/*_test.rb']
    t.verbose = true
  end

  desc 'Run RuboCop'
  task :rubocop do
    sh 'rubocop'
  end

  task default: %i[test rubocop]
rescue LoadError => e
  warn "Could not load rake/testtask: #{e}"
end
