require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class TestRandom < Minitest::Test

  GET_PARAMS = {
    :method => 'GET',
    :host => 'example.com',
    :id => '310bd66b-acc6-4aeb-affc-f53ed3753c45',
    :path => "/some/path",
    :query_string => "foo=bar",
    :body => nil,
    :content_type => "application/json"
  }

  POST_PARAMS = {
    :method => 'POST',
    :host => 'example.com',
    :id => 'd56c7cd2-7eed-4d16-8d34-e8f730a40042',
    :path => "/another/path",
    :query_string => "foo=bar",
    :body => 'tbd: yes',
    :content_type => "application/json"
  }

  def setup
    # create a couple of requests
    hmac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')

    # This is functionally equivalent to *GET_PARAMS.values, but it seems good to be explicit here?
    @req_get = hmac.prepare_request_headers(
                GET_PARAMS[:method],
                GET_PARAMS[:host],
                GET_PARAMS[:id],
                GET_PARAMS[:path],
                GET_PARAMS[:query_string],
                GET_PARAMS[:body],
                GET_PARAMS[:content_type]
              )
    #puts req_get.inspect
    # {"Authorization"=>"acquia-http-hmac realm=\"TestRealm\",id=\"310bd66b-acc6-4aeb-affc-f53ed3753c45\",timestamp=\"1432232899.529658\",nonce=\"c8d883d3-f4ee-459e-a5ee-4b95b0ee2454\",version=\"2.0\",signature=\"7ww60L1SJ6smIxgRbxYd1MwzQGzecuviq8NSvxb7FT8=\""}

    # Make this explicit too...
    @req_post = hmac.prepare_request_headers(*POST_PARAMS.values)
  end

  def test_get_no_body
    hmac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    assert hmac.valid_request?(
                            GET_PARAMS[:method],
                            GET_PARAMS[:host],
                            GET_PARAMS[:path],
                            @req_get['Authorization'],
                            GET_PARAMS[:query_string],
                            GET_PARAMS[:body],
                            GET_PARAMS[:content_type]
                         ), "valid_request? returned false for GET query"

  end

  def test_post_with_body
    # todo
  end

end
