require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class HmacVerifyTest < Minitest::Test

  def args_for_get
    {
      http_method: 'GET',
      host: 'example.com',
      id: '310bd66b-acc6-4aeb-affc-f53ed3753c45',
      path_info: "/some/path",
      query_string: "foo=bar",
    }
  end

  def test_simple_get
    mac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')
    headers = mac.prepare_request_headers(args_for_get)
    assert(headers['Authorization'], 'Did not get an Authorization header string')
    # Close the loop
    attributes = Acquia::HTTPHmac::Auth.parse_auth_header(headers['Authorization'])
    assert(mac.request_authorized?(attributes, args_for_get))
  end
end
