require 'openssl'
require 'base64'
require 'securerandom'
require 'uri'

module Acquia
  module HTTPHmac
    VERSION = '2.0'

    class Auth

      def initialize(realm, base64_secret)
        @realm = realm
        @secret = Base64.decode64(base64_secret)
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
      #   - body: The request body (omit or leave empty for normal GET/HEAD requests).
      #   - content_type: the value being set for Content-Type header.
      #   - headers: a has of additional headers to sign.
      def prepare_request_headers(args = {})
        merged_args = {
          http_method: nil,
          host: nil,
          id: nil,
          path_info: '/',
          query_string: '',
          body: '',
          content_type: '',
          headers: {},
          body_hash: nil,
          version: VERSION,
        }.merge(args)
        # Replace args so that the calling method gets all the values.
        args.replace(merged_args)
        args[:timestamp] ||= Time.now.to_i.to_s
        args[:nonce] ||= SecureRandom.uuid

        headers = {}
        headers['X-Authorization-Timestamp'] = args[:timestamp]
        unless args[:body].nil? || (args[:body].length == 0)
          args[:body_hash] = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(args[:body]))
          headers['X-Authorization-Content-SHA256'] = args[:body_hash]
        end
        # Discourage intermediate proxies from altering the content.
        headers['Cache-Control'] = 'no-transform'
        base_string = prepare_base_string(args)

        authorization = []
        authorization << "acquia-http-hmac realm=\"#{URI.encode(@realm)}\""
        authorization << "id=\"#{URI.encode(args[:id])}\""
        authorization << "nonce=\"#{args[:nonce]}\""
        authorization << "version=\"#{VERSION}\""
        authorization << "headers=\"#{args[:headers].keys.join(';')}\""
        authorization << "signature=\"#{signature(base_string)}\""
        headers['Authorization'] = authorization.join(',')
        headers
      end

      # Check if a request is authenticated.
      #
      # @param [Hash] args
      #   Expected keys with String values including values from the parsed request Authorization header
      #   - realm: The realm from the request
      #   - nonce: the nonce from the request
      #   - signature: the signature from the request
      #   - headers: [Hash] of additional String header names and values to be signed.
      #   - http_method: GET, POST, etc. Required.
      #   - host: the HTTP host name, like www.example.com. Required.
      #   - timestamp: Unix timestamp from the X-Authorization-Timestamp header
      #   - query_string: A query string for GET or HEAD requests.
      #   - content_type: the value being set for Content-Type header.
      def request_authenticated?(args = {})
        return false unless args[:realm] == @realm
        return false unless args[:nonce].match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)
        # Allow up to 900 sec (15 min) of clock skew by default.
        allowed_skew = args[:allowed_skew] || 900
        return false if (Time.now.to_i - args[:timestamp].to_i).abs > allowed_skew
        base_string = prepare_base_string(args)
        signature(base_string) == args[:signature]
      end

      # Check if a response is signed with the matching secret.
      #
      # @param [String] nonce
      #   Nonce from the *request* the caused this response.
      # @param [String] timestamp
      #   Timestamp from the *request* the caused this response.
      # @param body
      #   Body from the response.
      # @param signature
      #   Signature from the response headers.
      # @return [bool]
      def response_authenticated?(nonce:, timestamp:, body:, signature:)
        base_string = [nonce, timestamp, body].join("\n")
        signature(base_string) == signature
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
      #   - headers: a hash containing additional header name/value pairs to be included.
      def prepare_base_string(args = {})
        base_string_parts = [args[:http_method], args[:host].downcase, args[:path_info]]
        base_string_parts << args[:query_string]
        base_string_parts << "id=#{URI.encode(args[:id])}&nonce=#{args[:nonce]}&realm=#{URI.encode(@realm)}&version=#{args[:version]}"
        headers = args[:headers].to_a.sort do |x,y|
          (key_x, val_x) = x
          (key_y, val_y) = y
          key_x.downcase <=> key_y.downcase
        end
        headers.each do |h|
          (name, value) = h
          base_string_parts << "#{name.downcase}:#{value.strip}"
        end
        base_string_parts << args[:timestamp]
        unless args[:body_hash].nil?
          base_string_parts << args[:content_type].downcase
          base_string_parts << args[:body_hash]
        end
        base_string_parts.join("\n")
      end

      def self.parse_auth_header(header)
        attributes = {
          id: '',
          headers: '',
          nonce: '',
          realm: '',
          signature: '',
          version: '',
        }
        header.to_s.sub(/^acquia-http-hmac\s+/, '').split(/,\s*/).each do |value|
          m = value.match(/^(\w+)\=\"([^\"]*)\"$/)
          break unless m
          attributes[m[1].to_sym] = URI.decode(m[2])
        end
        # Re-format custom headers to hash keys.
        parts = attributes[:headers].split(';')
        attributes[:headers] = {}
        parts.each { |name| attributes[:headers][name] = '' }
        attributes
      end

      def signature(base_string)
        Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @secret, base_string))
      end
    end
  end
end
