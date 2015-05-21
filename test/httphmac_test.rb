require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class TestHTTPHmac < Minitest::Test

  def test_normalize_query
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    query_string = 'base=foo&all'
    assert_equal(mac.normalize_query(query_string), 'all=&base=foo')
    query_string = 'page=1&base=foo&all&base=zzz'
    assert_equal(mac.normalize_query(query_string), 'all=&base=foo&base=zzz&page=1')
    query_string = 'page=1&base=foo&all&base=zzz&base=foo'
    assert_equal(mac.normalize_query(query_string), 'all=&base=foo&base=foo&base=zzz&page=1')
    query_string = 'page=1&base=foo&all&base=z"z"z'
    assert_equal(mac.normalize_query(query_string), 'all=&base=foo&base=z%22z%22z&page=1')
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
    # Use known nonce and timestamp
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    mac.nonce = "f2c91a46-b505-4b50-afa2-21364dc8ab34"
    mac.timestamp = "1432180014.074019"
    body = '{"method":"hi.bob","params":["5","4","8"]}'
    content_type = 'application/json'
    headers = mac.prepare_request_headers('POST', 'www.example.com', 'test', '/hello', '', body, content_type)
    auth_header = headers['Authorization']
    assert(auth_header.match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version="2\.0",signature="[^"]+"/)
    assert_equal(headers['X-Acquia-Content-SHA256'], "6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo=")
    # We expect the following base string:
    # POST
    # www.example.com
    # /hello
    # id=test&nonce=f2c91a46-b505-4b50-afa2-21364dc8ab34&realm=TestRealm&timestamp=1432180014.074019&version=2.0
    # application/json
    # 6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo=
    m = auth_header.match(/.*,signature="([^"]+)"$/)
    assert_equal(m[1],"hptWaxZAXyB1G+p9P3uQTJe/DpD39XRKCcvmXOvaPBk=")
  end

end
