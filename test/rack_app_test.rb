require 'minitest/autorun'
require 'rack/test'

require_relative '../lib/acquia-http-hmac/rack_authenticate'
require_relative '../example/app'

class TestRackApp < Minitest::Test
  include Rack::Test::Methods

  def get_password_storage
    @passwords ||= Acquia::HTTPHmac::FilePasswordStorage.new(File.dirname(__FILE__) + '/../example/passwords.yml')
  end

  # Helper method
  def prepare_get(id, password, args = {})
    mac = Acquia::HTTPHmac::Auth.new('Test', password)
    args = {
      http_method: 'GET',
      host: 'example.org', # Default in the Rack test
      id: id,
      path_info: '/hello',
    }.merge(args)
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    args
  end

  # Helper method
  def prepare_post(id, password, body, args = {})
    mac = Acquia::HTTPHmac::Auth.new('Test', password)
    args = {
      http_method: 'POST',
      host: 'example.org', # Default in the Rack test
      id: id,
      path_info: '/hello',
      body: body,
      content_type: 'application/json',
    }.merge(args)
    mac.prepare_request_headers(args).each do |name, value|
      header(name, value)
    end
    header('content-type', args[:content_type])
    args
  end

  # Add just the auth middleware
  def app
    passwords = get_password_storage
    Rack::Builder.new {
      map "/" do
        # Need this base middleware so that request.logger is defined.
        use Rack::NullLogger
        use Acquia::HTTPHmac::RackAuthenticate, :password_storage => passwords, :realm => 'Test', :nonce_checker => Acquia::HTTPHmac::MemoryNonceChecker.new
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

  def test_403_bad_authorization_header
    # Add a basic auth header.
    header('Authorization', 'Basic Zm9vOmJhcmJheg==')
    get '/hello'
    assert_equal(403, last_response.status, "Didn't get a 403 response code")
  end

  def test_403_bad_password_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Use an invalid password by adding a letter.
    prepare_get(id, 'a' + passwords.data(id)['password'])
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_403_bad_id_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Use an invalid id by adding a letter.
    prepare_get(id + 'a', passwords.data(id)['password'])
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_403_bad_nonce_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Use an invalid nonce, not a UUID.
    prepare_get(id, passwords.data(id)['password'], nonce: 'wxyz')
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_403_duplicate_nonce_get
    passwords = get_password_storage
    id = passwords.ids.first
    nonce = SecureRandom.uuid
    prepare_get(id, passwords.data(id)['password'], nonce: nonce)
    get '/hello'
    assert_equal(200, last_response.status)
    # Repeat with the same nonce.
    prepare_get(id, passwords.data(id)['password'], nonce: nonce)
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_403_missing_header_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => 'nick'})
    get '/hello'
    # The expected header was missing.
    assert_equal(403, last_response.status)
  end

  def test_403_mismatched_header_get
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => 'nick'})
    # The expected header has a different value.
    header('X-Custom-Foo', 'nack')
    get '/hello'
    assert_equal(403, last_response.status)
  end

  def test_simple_get
    passwords = get_password_storage
    passwords.ids.each do |id|
      args = prepare_get(id, passwords.data(id)['password'])
      get '/hello'
      assert_equal(200, last_response.status)
      response_hmac = nil
      last_response.headers.each do |name, value|
        if name.downcase == 'x-acquia-content-hmac-sha256'
          response_hmac = value
          break
        end
      end
      assert(response_hmac, 'Did not find response HMAC header')
      mac = Acquia::HTTPHmac::Auth.new('Test', passwords.data(id)['password'])
      assert_equal(response_hmac, mac.signature(args[:nonce] + "\n" + last_response.body))
    end
  end

  def test_get_with_extra_header
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => 'nick'})
    header('X-Custom-Foo', 'nick')
    get '/hello'
    assert_equal(200, last_response.status)
  end

  def test_get_with_quoted_header
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => '"nick"'})
    header('X-Custom-Foo', '"nick"')
    get '/hello'
    assert_equal(200, last_response.status)
  end

  def test_get_with_spaces_in_header
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => 'a b c '})
    header('X-Custom-Foo', ' a b c   ')
    get '/hello'
    assert_equal(200, last_response.status)
  end

  def test_get_with_spaces_in_quoted_header
    passwords = get_password_storage
    id = passwords.ids.first
    # Pass a header expected to be signed.
    prepare_get(id, passwords.data(id)['password'], headers: {'X-Custom-Foo' => '"hi nick" '})
    header('X-Custom-Foo', ' "hi nick"   ')
    get '/hello'
    assert_equal(200, last_response.status)
  end

  def test_simple_post
    passwords = get_password_storage
    passwords.ids.each do |id|
      body = '{"hello":"hi.bob","params":["5","4","8"]}'
      prepare_post(id, passwords.data(id)['password'], body)
      post '/hello', body
      assert_equal(201, last_response.status)
    end
  end

  def test_403_bad_body_post
    passwords = get_password_storage
    id = passwords.ids.first
    body = '{"hello":"hi.bob","params":["5","4","8"]}'
    prepare_post(id, passwords.data(id)['password'], body)
    # Create a mismatch by adding an extra character to the body.
    post '/hello', body + 'a'
    assert_equal(403, last_response.status)
  end
end
