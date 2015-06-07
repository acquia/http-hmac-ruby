require 'minitest/autorun'
require_relative 'helpers/rack_app_test_base'

class TestRackApp < Minitest::Test
  include TestRackAppBase

  def get_password_storage
    @passwords ||= Acquia::HTTPHmac::FilePasswordStorage.new(File.dirname(__FILE__) + '/../fixtures/passwords.yml')
  end

  def get_password(id, timestamp = nil)
    get_password_storage.data(id)['password']
  end
end
