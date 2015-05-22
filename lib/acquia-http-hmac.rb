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

      # Prepare client-side request headers.
      #
      # @param [Hash] args
      #   Supported keys with String values:
      #   - http_method: GET, POST, etc. Required.
      #   - host: the HTTP host name, like www.example.com. Required.
      #   - id: the client id or API key identifying the requestor. Required.
      #   - path_info: The request path with leading slash.
      #   - query_string: A query string for GET or HEAD requests.
      #   - body: The request body for non-GET/HEAD.
      #   - content_type: the value being set for Content-Type header.
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

      # Check if a request is aithorized.
      #
      # @param [Hash] auth_attributes
      #   The value of the parsed request Authorization header
      # @param [Hash] args
      #    Must include :body_hash param with value of X-Acquia-Content-SHA256 if present
      #    May include :drift_window to override default value of 5 seconds

      def request_authorized?(auth_headers = {}, args = {})
        # Make sure the timestamp is valid
        delta_t = (args[:timestamp].to_f - Time.now.to_f).abs
        drift_window = args[:drift_window] ? args[:drift_window].to_f : 5.0
        return false unless (delta_t) < drift_window

        # Validate the signature
        sig = signature(prepare_base_string(args))
        sig == auth_headers[:signature]
      end

      # Common helper method for creating the string to sign.
      #
      # @param [Hash] args
      #   Supported keys with String values:
      #   - http_method: GET, POST, etc. Required.
      #   - host: the HTTP host name, like www.example.com. Required.
      #   - id: the client id or API key identifying the requestor. Required.
      #   - path_info: The request path with leading slash.
      #   - query_string: A query string for GET or HEAD requests.
      #   - body_hash: The sha-256 of the request body for non-GET/HEAD.
      #   - content_type: the value being set for Content-Type header.
      #   - nonce: a UUID
      #   - timestamp: a UNIX timpstamp as float with microsecond precision.
      def prepare_base_string(args = {})
        args[:http_method].upcase!
        base_string_parts = [args[:http_method], args[:host].downcase, args[:path_info]]
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

      def self.parse_auth_header(header)
        attributes = {}
        header.to_s.sub(/^acquia-http-hmac\s+/, '').split(/,\s*/).each do |value|
          m = value.match(/^(\w+)\=\"([^\"]*)\"$/)
          attributes[m[1].to_sym] = URI.decode(m[2])
        end
        attributes
      end

      # Helper method for sorting the query string for signing.
      #
      # @param [String] query_string
      def normalize_query(query_string)
        normalized = ''
        parts = query_string.split('&').map do |p|
          unless p.include?('=')
            p << '='
          end
          p.split('=', 2)
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
