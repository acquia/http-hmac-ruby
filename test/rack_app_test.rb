require 'minitest/autorun'
require 'rack/test'

require_relative '../lib/acquia-http-hmac/rack_authenticate'
require_relative '../example/app'

class TestRackApp < Minitest::Test
  include Rack::Test::Methods

  # Add just the auth middleware
  def app
    Rack::Builder.new {
      passwords = Acquia::HTTPHmac::FilePasswordStorage.new(File.dirname(__FILE__) + '/../example/passwords.yml')

      map "/" do
        # Need this base middleware so that request.logger is defined.
        use Rack::NullLogger
        use Acquia::HTTPHmac::RackAuthenticate, :password_storage => passwords, :realm => 'Test'
        run Example::App
      end
    }.to_app
  end

  def test_simple_get
    mac = Acquia::HTTPHmac::Auth.new('Test', 'foopassword')
    args = {
      http_method: 'GET',
      host: 'example.org', # Default in the Rack test
      id: 'testuser',
      path_info: '/hello',
    }
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    get '/hello'
    assert_equal(200, last_response.status)
  end

  def test_simple_post
    mac = Acquia::HTTPHmac::Auth.new('Test', 'foopassword')
    body = '{"method":"hi.bob","params":["5","4","8"]}'
    args = {
      http_method: 'POST',
      host: 'example.org', # Default in the Rack test
      id: 'testuser',
      path_info: '/hello',
      body: body,
      content_type: 'application/json',
    }
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    header('content-type', 'application/json')
    post '/hello', body
    assert_equal(201, last_response.status)
  end
end
