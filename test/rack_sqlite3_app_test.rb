require 'minitest/autorun'
require 'base64'
require 'openssl'
require_relative 'helpers/rack_app_test_base'
require_relative '../example-sqlite3/setup'
require 'acquia-http-hmac/sqlite3_password_storage'

class TestSqlite3RackApp < Minitest::Test
  include TestRackAppBase

  def setup
    @dbfile = File.join(File.dirname(__FILE__), '/../fixtures/passwords.sqlite3')
    @passwords_file = File.dirname(__FILE__) + '/../fixtures/passwords.yml'
    s = ExampleSQLite3Setup.new(@dbfile, @passwords_file)
    s.write_database
    @binary_passwords = {}
    YAML.safe_load(File.read(@passwords_file)).each do |id,data|
      @binary_passwords[id] = Base64.decode64(data['password'])
    end
  end

  def get_password(id, timestamp = nil)
    ts = Time.now.to_i
    date = Time.at(ts).utc.strftime('%F')
    realm = 'Test'
    # Run a 2-step HMAC KDF using date and realm
    sha256 = OpenSSL::Digest::SHA256.new
    derived_pass1 = OpenSSL::HMAC.digest(sha256, @binary_passwords[id], date)
    derived_pass2 = OpenSSL::HMAC.digest(sha256, derived_pass1, realm)
    Base64.strict_encode64(derived_pass2)
  end

  def get_password_storage
    @storage ||= Acquia::HTTPHmac::SQLite3PasswordStorage.new(@dbfile)
  end

end
