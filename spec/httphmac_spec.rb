require_relative '../lib/httphmac'

describe "the crypto subroutines" do


  it "should compute a valid auth header" do
    mac = Acquia::HTTPHmac.new('TestRealm', 'thesecret')
    header = mac.prepare_request('GET', 'www.example.com', 'test', '/hello')
    expect(header).to match /acquia-http-hmac realm="TestRealm",id="test",timestamp="[0-9.]+",nonce="[0-9a-f-]+",version=2\.0,signature=".+"/ 
  end

end
