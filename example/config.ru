#!/usr/bin/env rackup -p8010

require "bundler/setup"
Bundler.require

require_relative 'app'
require 'acquia-http-hmac/rack_authenticate'

unless ENV['NO_AUTHENTICATION']
  passwords = Acquia::HTTPHmac::FilePasswordStorage.new(File.dirname(__FILE__) + '/../fixtures/passwords.yml')
  options = {
    password_storage: passwords,
    realm: 'Test',
    nonce_checker: Acquia::HTTPHmac::MemoryNonceChecker.new,
    excluded_paths: ['/healthcheck'],
  }
  use Acquia::HTTPHmac::RackAuthenticate, options
end
run Example::App
