require 'yaml'
require 'openssl'
require 'base64'
require_relative '../acquia-http-hmac'

module Acquia
  module HTTPHmac
    class RackAuthenticate
      def initialize(app, options)
        @password_storage = options[:password_storage]
        @realm = options[:realm]
        @nonce_checker = options[:nonce_checker]
        @excluded_paths = options[:excluded_paths]
        @app = app
      end

      def call(env)
        # Skip paths based on a list of prefixes.
        if @excluded_paths && env['PATH_INFO'].start_with?(*@excluded_paths)
          return @app.call(env)
        end
        auth_header = env['HTTP_AUTHORIZATION'].to_s
        return unauthorized if auth_header.empty?

        attributes = Acquia::HTTPHmac::Auth.parse_auth_header(auth_header)
        return denied('Invalid nonce') unless @nonce_checker.valid?(attributes[:id], attributes[:nonce])
        args = args_for_authenticator(env, attributes)
        mac = message_authenticator(args[:id], args[:timestamp])
        return denied('Invalid credentials') unless mac && mac.request_authenticated?(args)

        return denied('Invalid body') unless valid_body?(env)

        # Pass the id & data to later stages
        env['ACQUIA-HTTP-HMAC-ID'] = attributes[:id]
        env['ACQUIA-HTTP-HMAC-DATA'] = @password_storage.data(attributes[:id])
        (status, headers, resp_body) = @app.call(env)
        sign_response(status, headers, resp_body, args[:nonce], args[:timestamp], mac)
      end

      private

      def unauthorized
        [ 401,
          {
            'Content-Type' => 'text/plain',
            'Content-Length' => '0',
            'WWW-Authenticate' => 'acquia-http-hmac realm="'+ @realm +'"'
          },
          []
        ]
      end

      def denied(message)
        [ 403,
          {
            'Content-Type' => 'text/plain',
            'Connection' => 'close',
          },
          [message]
        ]
      end

      def message_authenticator(id, timestamp)
        mac = nil
        if @password_storage.valid?(id)
          mac = Acquia::HTTPHmac::Auth.new(@realm, @password_storage.password(id, timestamp))
        end
        mac
      end

      def args_for_authenticator(env, attributes)
        request = Rack::Request.new(env)
        args = {
          host: request.host_with_port,
          query_string: request.query_string,
          http_method: request.request_method,
          path_info: request.path_info,
          content_type: request.content_type,
          body_hash: env['HTTP_X_AUTHORIZATION_CONTENT_SHA256'],
          timestamp: env['HTTP_X_AUTHORIZATION_TIMESTAMP'].to_i,
        }.merge(attributes)
        # Map expected header names to the key that would be in env.
        attributes[:headers].keys.each do |name|
          key = 'HTTP_' + name.gsub('-', '_').upcase
          args[:headers][name] = env[key] if env[key]
        end
        args
      end

      def valid_body?(env)
        request = Rack::Request.new(env)
        # Read the incoming request IO stream.
        body = request.body.read
        # Allow other middleware to access the body also.
        request.body.rewind if request.body.respond_to?(:rewind)
        if body.empty? && env['HTTP_X_AUTHORIZATION_CONTENT_SHA256'].nil?
          # No body to validate
          true
        else
          body_hash = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(body))
          body_hash == env['HTTP_X_AUTHORIZATION_CONTENT_SHA256']
        end
      end

      # Add a hmac signature over the resonse body.
      #
      # @param [Int] status
      # @param [Hash] headers
      # @param [Enumerable] resp_body
      # @param [String] attributes
      # @param [Acquia::HTTPHmac::Auth] mac
      #
      # @return Array
      def sign_response(status, headers, resp_body, nonce, timestamp, mac)
        final_body = ''
        # Rack defines the response body as implementing #each
        resp_body.each { |part| final_body << part.to_s }
        # Use the request nonce to sign the response.
        headers['X-Server-Authorization-HMAC-SHA256'] = mac.signature(nonce + "\n" + timestamp.to_s + "\n" + final_body)
        # Nobody should be changing or caching this response.
        headers['Cache-Control'] = 'no-transform, no-cache, no-store, private, max-age=0'
        [status, headers, [final_body]]
      end

    end

    ### The classes below are primarily for testing.

    class SimplePasswordStorage

      def initialize(creds = {})
        @@creds = creds
      end

      def valid?(id)
        !!@@creds[id]
      end

      # Fetch the password using the id and timestamp from the request.
      #
      # @param [String] id
      #   An arbitrary identifier.
      # @param [Integer] timestamp
      #   A unix timestamp. The returned password may be different based on
      #   the current date or time.
      def password(id, timestamp)
        fail('Invalid id') unless @@creds[id] && @@creds[id]['password']
        @@creds[id]['password']
      end

      def data(id)
        fail('Invalid id') unless @@creds[id]
        @@creds[id]
      end

      def ids
        @@creds.keys
      end
    end

    class FilePasswordStorage < SimplePasswordStorage

      def initialize(filename)
        creds = {}
        if File.exist?(filename)
          creds = YAML.safe_load(File.read(filename))
        end
        super(creds)
      end
    end

    class NoopNonceChecker
      def valid?(id, nonce)
        nonce.length == 36
      end
    end

    class MemoryNonceChecker
      def initialize
        @@seen = {}
      end

      def valid?(id, nonce)
        # A UUID is 36 characters.
        return false unless nonce.length == 36
        @@seen[id] ||= {}
        valid = !@@seen[id][nonce]
        @@seen[id][nonce] = Time.now.to_i
        valid
      end
    end
  end
end

