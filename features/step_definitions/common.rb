Given /^the endpoint "(.*?)" "(.*?)"$/ do |method, path|
	@method = method
	@path = path
end

Given /^the header "(.*?)" "(.*?)"$/ do |key, value|
	@headers = Hash.new unless @headers
	@headers[key] = value
end

Given /^the custom header "(.*?)" "(.*?)"$/ do |key, value|
	@cheaders = Hash.new unless @cheaders
	@cheaders[key] = value
	@headers = Hash.new unless @headers
	@headers[key] = value
end

Given /^the body "(.*?)"$/ do |body|
	@body = body
end

When /^I sign the request with the "(.*?)" digest and secret key "(.*?)"$/ do |digest, key|
	signer = Acquia::HTTPHmac.new(@method, @body, @headers, @cheaders, @path)
	key = key
	case digest
	when "SHA-1"
		digester = Digest::SHA1
	when "SHA1"
		digester = Digest::SHA1
	when "SHA-256"
		digester = Digest::SHA256
	when "SHA256"
		digester = Digest::SHA256
	end
	@signature = signer.sign(digester, key)
end

Then /^I should see the signature "(.*?)"$/ do |signature|
	expect(@signature).to eq(signature)
end