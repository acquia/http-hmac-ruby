require 'yaml'
require_relative '../acquia-http-hmac'

module Acquia
  module HTTPHmac
    class RackAuthenticate
      def initialize(app, options)
        @creds_provider = options[:creds_provider]
        @app = app
      end

      def call(env)
        request = Rack::Request.new(env)
        request.params # contains the union of GET and POST params
        body = request.body   # the incoming request IO stream
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

