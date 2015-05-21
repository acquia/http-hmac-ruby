require 'openssl'
require 'base64'
require 'securerandom'
require 'uri'

module Acquia
  module HTTPHmac
    VERSION = '2.0'

    class Auth
      # These accessors are normally just for unit testing
      attr_accessor :nonce, :timestamp

      def initialize(realm, secret)
        @realm = realm
        @secret = secret
      end

      def prepare_request_headers(http_method, host, id, path_info= '/', query_string = '', body = '', content_type = '')
        headers = {}
        http_method = http_method.upcase
        base_string_parts = [http_method, host, path_info]
        @timestamp ||= "%0.6f" % Time.now.to_f
        @nonce ||= SecureRandom.uuid
        base_string_parts << "id=#{URI.encode(id)}&nonce=#{nonce}&realm=#{URI.encode(@realm)}&timestamp=#{timestamp}&version=#{VERSION}"
        if ['GET', 'HEAD'].include?(http_method)
          unless query_string.empty?
            base_string_parts << normalize_query(query_string)
          end
        else
          base_string_parts << content_type.downcase
          body_hash = Base64.encode64(OpenSSL::Digest::SHA256.digest(body)).strip
          headers['X-Acquia-Content-SHA256'] = body_hash
          base_string_parts << body_hash
        end
        base_string = base_string_parts.join("\n")

        authorization = []
        authorization << "acquia-http-hmac realm=\"#{URI.encode(@realm)}\""
        authorization << "id=\"#{URI.encode(id)}\""
        authorization << "timestamp=\"#{@timestamp}\""
        authorization << "nonce=\"#{@nonce}\""
        authorization << "version=\"#{VERSION}\""
        authorization << "signature=\"#{signature(base_string)}\""
        headers['Authorization'] = authorization.join(',')
        headers
      end

      def valid_request?(http_method, host, path_info, authorization_header, query_string = '', body = '', content_type = '')
        raise "Missing Authorization header!" if !authorization_header || authorization_header.empty?
        prepare_request_headers(
                                http_method,
                                host,
                                authorization_header['id'],
                                path_info,
                                query_string,
                                body,
                                content_type
                               )
        end
      end

      def parse_auth_header(header)
        attributes = {}
        header.to_s.sub(/^acquia-http-hmac\s+/, '').split(/,\s*/).each do |value|
          m = value.match(/^(\w+)\=\"([^\"]*)\"$/)
          attributes[m[1].to_sym] = URI.decode(m[2])
        end
        attributes
      end

      def normalize_query(query_string)
        normalized = ''
        parts = query_string.split('&').map do |p|
          unless p.include?('=')
            p << '='
          end
           URI.encode(p).split('=', 2)
        end
        sorted_parts = parts.sort do |x, y|
          (key_x, val_x) = x
          (key_y, val_y) = y
          if key_x == key_y
            val_x <=> val_y
          else
            key_x <=> key_y
          end
        end
        normalized = sorted_parts.map {|p| "#{p[0]}=#{p[1]}" }.join('&')
      end

      def signature(base_string)
        Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @secret, base_string)).strip
      end
    end
  end
end
