require 'openssl'
require 'base64'
require 'securerandom'
require 'uri'

module Acquia
  module HTTPHmac
    VERSION = '2.0'

    class Auth

      def initialize(realm, secret)
        @realm = realm
        @secret = secret
      end

      def prepare_request_headers(args = {})
        args = {
          http_method: nil,
          host: nil,
          id: nil,
          path_info: '/',
          query_string: '',
          body: '',
          content_type: '',
          body_hash: nil,
        }.merge(args)
        args[:http_method].upcase!
        args[:timestamp] ||= "%0.6f" % Time.now.to_f
        args[:nonce] ||= SecureRandom.uuid

        headers = {}
        unless ['GET', 'HEAD'].include?(args[:http_method])
          args[:body_hash] = Base64.encode64(OpenSSL::Digest::SHA256.digest(args[:body])).strip
          headers['X-Acquia-Content-SHA256'] = args[:body_hash]
        end
        base_string = prepare_base_string(args)

        authorization = []
        authorization << "acquia-http-hmac realm=\"#{URI.encode(@realm)}\""
        authorization << "id=\"#{URI.encode(args[:id])}\""
        authorization << "timestamp=\"#{args[:timestamp]}\""
        authorization << "nonce=\"#{args[:nonce]}\""
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

      def prepare_base_string(args = {})
        args[:http_method].upcase!
        base_string_parts = [args[:http_method], args[:host], args[:path_info]]
        base_string_parts << "id=#{URI.encode(args[:id])}&nonce=#{args[:nonce]}&realm=#{URI.encode(@realm)}&timestamp=#{args[:timestamp]}&version=#{VERSION}"
        if ['GET', 'HEAD'].include?(args[:http_method])
          unless args[:query_string].empty?
            base_string_parts << normalize_query(args[:query_string])
          end
        else
          base_string_parts << args[:content_type].downcase
          base_string_parts << args[:body_hash]
        end
        base_string_parts.join("\n")
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
