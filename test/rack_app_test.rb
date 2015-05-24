require 'minitest/autorun'
require 'rack/test'

require_relative '../lib/acquia-http-hmac/rack_authenticate'
require_relative '../example/app'

class TestRackApp < Minitest::Test
  include Rack::Test::Methods

  def get_password_storage
    @passwords ||= Acquia::HTTPHmac::FilePasswordStorage.new(File.dirname(__FILE__) + '/../example/passwords.yml')
  end

  # Add just the auth middleware
  def app
    passwords = get_password_storage
    Rack::Builder.new {
      map "/" do
        # Need this base middleware so that request.logger is defined.
        use Rack::NullLogger
        use Acquia::HTTPHmac::RackAuthenticate, :password_storage => passwords, :realm => 'Test'
        run Example::App
      end
    }.to_app
  end

  def test_401_get
    # Don't add any headers.
    get '/hello'
    assert_equal(401, last_response.status, "Didn't get a 401 response code")
    assert(last_response.headers['WWW-Authenticate'], "Didn't get a WWW-Authenticate header in the response")
  end

  def test_403_bad_password_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Use an invalid password by adding a letter.
    mac = Acquia::HTTPHmac::Auth.new('Test', passwords.data(id)['password'] + 'a')
    args = {
      http_method: 'GET',
      host: 'example.org', # Default in the Rack test
      id: id,
      path_info: '/hello',
    }
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_403_bad_id_get
    passwords = get_password_storage
    id = passwords.ids.first
    mac = Acquia::HTTPHmac::Auth.new('Test', passwords.data(id)['password'])
    # Use an invalid id by adding a letter.
    args = {
      http_method: 'GET',
      host: 'example.org', # Default in the Rack test
      id: id + 'a',
      path_info: '/hello',
    }
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_simple_get
    passwords = get_password_storage
    passwords.ids.each do |id|
      mac = Acquia::HTTPHmac::Auth.new('Test', passwords.data(id)['password'])
      args = {
        http_method: 'GET',
        host: 'example.org', # Default in the Rack test
        id: id,
        path_info: '/hello',
      }
      mac.prepare_request_headers(args).each do |name, value|
        header(name, value)
      end
      get '/hello'
      assert_equal(200, last_response.status)
    end
  end

  def test_simple_post
    passwords = get_password_storage
    passwords.ids.each do |id|
      mac = Acquia::HTTPHmac::Auth.new('Test', passwords.data(id)['password'])
      body = '{"method":"hi.bob","params":["5","4","8"]}'
      args = {
        http_method: 'POST',
        host: 'example.org', # Default in the Rack test
        id: id,
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
end
