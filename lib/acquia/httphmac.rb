require 'digest'

module Acquia
	class HTTPHmac
		def initialize(method, body, headers, customheaders, path)
			body = "" unless body
			md5 = Digest::MD5.hexdigest body
			headers = Hash.new unless headers
			if headers["Content-Type"]
				ct = headers["Content-Type"].downcase
			else
				ct = ""
			end
			if headers["Date"]
				date = headers["Date"]
			else
				date = ""
			end
			@data = "#{method.upcase}\n#{md5}\n#{ct}\n#{date}\n"
			unless customheaders && customheaders.length 
				@data << "\n"
			else
				customheaders.each {|key, value|
					@data << "#{key.downcase}: #{value}\n"
				}
			end
			@data << path
		end

		def sign(digest, secret)
			hmaccer = Digest::HMAC.new(secret, digest)
			hmaccer.update(@data)
			return hmaccer.base64digest
		end
	end
end
