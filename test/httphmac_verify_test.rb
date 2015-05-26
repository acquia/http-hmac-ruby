require 'minitest/autorun'
require 'base64'
require_relative '../lib/acquia-http-hmac'

class HmacVerifyTest < Minitest::Test

  def get_params
    {
      :http_method => 'GET',
      :host => 'example.com',
      :id => '12345',
      :path_info => "/some/path",
      :query_string => "foo=bar",
      :body => nil,
      :content_type => "application/json",
      :nonce => '869a8b00-f96f-4a9e-98e6-a6e38b0de316',
      :timestamp => Time.now.to_i
    }
  end

  def post_params
    {
      :http_method => 'POST',
      :host => 'example.com',
      :id => '54321',
      :path_info => "/another/path",
      :query_string => "foo=bar",
      :body => 'tbd: yes',
      :content_type => "application/json",
      :nonce => '869a8b00-f96f-4a9e-98e6-a6e38b0de316',
      :timestamp => Time.now.to_i
    }
  end

  def setup
    # "dGhlc2VjcmV0" is base64 of 'thesecret'
    @secret = "dGhlc2VjcmV0"
    @realm = 'TestRealm'
    hmac = Acquia::HTTPHmac::Auth.new(@realm, @secret)

    @req_get = hmac.prepare_request_headers(get_params)
    @req_post = hmac.prepare_request_headers(post_params)
  end

  def test_get_no_body
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new(@realm, @secret)
    ret = hmac.request_authenticated?(header, get_params)
    assert(ret, "request_authenticated? failed for GET")
  end

  def test_it_fails_with_invalid_realm
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new('bad_realm', @secret)
    ret = hmac.request_authenticated?(header, get_params)
    assert(!ret, "request_authenticated? accepted invalid realm")
  end

  def test_it_fails_with_invalid_secret
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new(@realm, Base64.strict_encode64('wrong password'))
    ret = hmac.request_authenticated?(header, get_params)
    assert(!ret, "request_authenticated? accepted invalid secret")
  end

  def test_post_with_body
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_post['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new(@realm, @secret)
    ret = hmac.request_authenticated?(header, post_params.merge({:body_hash => @req_post['X-Acquia-Content-SHA256']}))
    assert(ret, "request_authenticated? failed for POST")
  end

  def test_it_requires_recent_timestamp
    # We need to do our own GET with a wrong timestamp here:
    params = get_params
    # Put it 901 seconds in the past.
    params[:timestamp] = params[:timestamp].to_i - 901
    hmac = Acquia::HTTPHmac::Auth.new(@realm, @secret)
    get = hmac.prepare_request_headers(params)
    header = Acquia::HTTPHmac::Auth::parse_auth_header(get['Authorization'])
    ret = hmac.request_authenticated?(header, params)
    assert(!ret, "request_authenticated? accepted old timestamp")
  end
end