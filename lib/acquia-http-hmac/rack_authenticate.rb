require_relative '../httphmac'

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
      end
    end
  end
end

