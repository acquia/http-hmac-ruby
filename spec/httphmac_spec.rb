require_relative '../lib/acquia-http-hmac'

describe "Acquia::HTTPHmac" do


  it "#prepare_request" do
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    header = mac.prepare_request('GET', 'www.example.com', 'test', '/hello')
    expect(header).to match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version=2\.0,signature=".+"/ 
  end

end
