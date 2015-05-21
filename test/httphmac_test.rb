require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class TestHTTPHmac < Minitest::Test

  def test_normalize_query
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    query_string = 'base=foo&all'
    assert_equal(mac.normalize_query(query_string), 'all=&base=foo')
  end

  def test_prepare_request_get
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    headers = mac.prepare_request_headers('GET', 'www.example.com', 'test', '/hello')
    auth_header = headers['Authorization']
    assert(auth_header.match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version="2\.0",signature="[^"]+"/)

    # Repeat with known nonce and timestamp
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    mac.nonce = "f2c91a46-b505-4b50-afa2-21364dc8ff34"
    mac.timestamp = "1432180014.074019"
    headers = mac.prepare_request_headers('GET', 'www.example.com', 'test', '/hello')
    auth_header = headers['Authorization']
    # We expect the following base string:
    # GET
    # www.example.com
    # /hello
    # id=test&nonce=f2c91a46-b505-4b50-afa2-21364dc8ff34&realm=TestRealm&timestamp=1432180014.074019&version=2.0
    m = auth_header.match(/.*,signature="([^"]+)"$/)
    assert(m, 'Did not find signature')
    # Compare to a signature calulated with the base string in PHP.
    assert_equal(m[1], "0oOg1jupjGm2jwNw3TbDGBGzY8gAuKp9uZ0EZHXeVWE=")
    # Repeast with a query string that needs to be normalized.
    query_string = 'base=foo&all'
    headers = mac.prepare_request_headers('GET', 'www.example.com', 'test', '/hello', query_string)
    auth_header = headers['Authorization']
    # We expect the following base string:
    # GET
    # www.example.com
    # /hello
    # id=test&nonce=f2c91a46-b505-4b50-afa2-21364dc8ff34&realm=TestRealm&timestamp=1432180014.074019&version=2.0
    # all=&base=foo
    m = auth_header.match(/.*,signature="([^"]+)"$/)
    assert(m, 'Did not find signature')
    # Compare to a signature calulated with the base string in PHP.
    assert_equal(m[1], "8xcsff99l6FYemE0B3Qs79TnOrTBh+j1fylBoKZgUls=")
  end

  def test_prepare_request_post
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    body = '{"method":"hi.bob","params":["5","4","8"]}'
    content_type = 'application/json'
    headers = mac.prepare_request_headers('POST', 'www.example.com', 'test', '/hello', '', body, content_type)
    auth_header = headers['Authorization']
    assert(auth_header.match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version="2\.0",signature="[^"]+"/)
    assert_equal(headers['X-Acquia-Content-SHA256'], Base64.encode64(OpenSSL::Digest::SHA256.digest(body)).strip)
    m = auth_header.match(/.*,signature="([^"]+)"$/)
  end

end