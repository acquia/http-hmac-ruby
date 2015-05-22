require 'yaml'
require_relative '../acquia-http-hmac'

module Acquia
  module HTTPHmac
    class RackAuthenticate
      def initialize(app, options)
        @creds_provider = options[:creds_provider]
        @realm = options[:realm]
        @app = app
      end

      def call(env)
        request = Rack::Request.new(env)
        request.query_string
        request.params # contains the union of GET and POST params
        puts request.host
        body = request.body   # the incoming request IO stream
        auth_header = env['HTTP_AUTHORIZATION']

        unless auth_header
         return [401, {}, ['WWW-Authenticate: acquia-http-hmac realm="'+ @realm +'"']]
        end

        attributes = Acquia::HTTPHmac::Auth.parse_auth_header(auth_header)
        args = {
          host: request.host_with_port,
          query_string: request.query_string,
          http_method: request.request_method,
          path_info: request.path_info,
        }
        mac = nil
        if @creds_provider.valid?(attributes[:id])
          mac = Acquia::HTTPHmac::Auth.new(@realm, @creds_provider.password(attributes[:id]))
        end
        unless mac && attributes[:realm] == @realm && mac.request_authorized?(attributes, args)
          return [403, {}, ['Invalid credentials']]
        end

        @app.call(env)
      end
    end

    class FileCredentialProvider

      def initialize(filename)
        @creds = {}
        if File.exist?(filename)
          @creds = YAML.safe_load(File.read(filename))
        end
      end

      def valid?(id)
        !!@creds[id]
      end

      def password(id)
        fail('Invalid id') unless @creds[id] && @creds[id]['password']
        @creds[id]['password']
      end

      def data(id)
        fail('Invalid id') unless @creds[id]
        @creds[id]
      end
    end
  end
end

