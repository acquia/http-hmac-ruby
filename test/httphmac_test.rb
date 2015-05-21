require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'


class TestHTTPHmac < Minitest::Test

  def test_prepare_request_get
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    header = mac.prepare_request('GET', 'www.example.com', 'test', '/hello')
    assert(header.match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version=2\.0,signature="[^"]+"/)

    # Repeat with known nonce and timestamp
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    mac.nonce = "f2c91a46-b505-4b50-afa2-21364dc8ff34"
    mac.timestamp = "1432180014.074019"
    header = mac.prepare_request('GET', 'www.example.com', 'test', '/hello')
    # We expect the following base string:
    # GET
    # www.example.com
    # /hello
    # id=test&nonce=f2c91a46-b505-4b50-afa2-21364dc8ff34&realm=TestRealm&timestamp=1432180014.074019&version=2.0
    m = header.match(/.*,signature="([^"]+)"$/)
    assert(m, 'Did not find signature')
    # Compare to a signature calulated with the base string in PHP.
    assert_equal(m[1], "0oOg1jupjGm2jwNw3TbDGBGzY8gAuKp9uZ0EZHXeVWE=")
  end

  def test_prepare_request_post
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    header = mac.prepare_request('POST', 'www.example.com', 'test', '/hello')
    assert(header.match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version=2\.0,signature=".+"/)
  end

end
