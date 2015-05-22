require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class ValidResponseTest < Minitest::Test

  GET_PARAMS = {
    :http_method => 'GET',
    :host => 'example.com',
    :id => '12345',
    :path_info => "/some/path",
    :query_string => "foo=bar",
    :body => nil,
    :content_type => "application/json",
    :nonce => '869a8b00-f96f-4a9e-98e6-a6e38b0de316',
    :timestamp => Time.now.to_f
  }

  POST_PARAMS = {
    :http_method => 'POST',
    :host => 'example.com',
    :id => '54321',
    :path_info => "/another/path",
    :query_string => "foo=bar",
    :body => 'tbd: yes',
    :content_type => "application/json",
    :nonce => '869a8b00-f96f-4a9e-98e6-a6e38b0de316',
    :timestamp => Time.now.to_f
  }

  def setup
    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')

    @req_get = hmac.prepare_request_headers(GET_PARAMS)
    @req_post = hmac.prepare_request_headers(POST_PARAMS)
  end

  def test_get_no_body
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')
    ret = hmac.request_authorized?(header, GET_PARAMS)
    assert ret, "request_authorized? failed for GET"
  end

  def test_it_fails_with_invalid_realm
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new('bad_realm', 'thesecret')
    ret = hmac.request_authorized?(header, GET_PARAMS)
    assert ret == false, "request_authorized? accepted invalid realm"
  end

  def test_it_fails_with_invalid_secret
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_get['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'wrong password')
    ret = hmac.request_authorized?(header, GET_PARAMS)
    assert ret == false, "request_authorized? accepted invalid secret"
  end

  def test_post_with_body
    header = Acquia::HTTPHmac::Auth::parse_auth_header(@req_post['Authorization'])
    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')
    ret = hmac.request_authorized?(header, POST_PARAMS.merge({:body_hash => @req_post['X-Acquia-Content-SHA256']}))
    assert ret, "request_authorized? failed for POST"
  end

  def test_it_requires_recent_timestamp
    # We need to do our own GET with a wrong timestamp here:
    params = GET_PARAMS.merge({:timestamp => GET_PARAMS[:timestamp].to_f - 6.0})

    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')
    get = hmac.prepare_request_headers(params)
    header = Acquia::HTTPHmac::Auth::parse_auth_header(get['Authorization'])
    ret = hmac.request_authorized?(header, params)
    assert ret == false, "request_authorized? accepted old timestamp"
  end

  def test_drift_window_overrides
    # We need to do our own GET with a wrong timestamp here:
    params = GET_PARAMS.merge({:timestamp => GET_PARAMS[:timestamp].to_f - 6.0})

    hmac = Acquia::HTTPHmac::Auth.new('TestRealm', 'thesecret')
    get = hmac.prepare_request_headers(params)
    header = Acquia::HTTPHmac::Auth::parse_auth_header(get['Authorization'])
    ret = hmac.request_authorized?(header, params.merge({:drift_window => 10}))
    assert ret, "request_authorized? did not accept :drift_window override"
  end

end