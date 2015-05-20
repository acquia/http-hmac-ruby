require_relative '../httphmac'

module Rack
  module Acquia
    class HTTPHmac

      def initialize(app, options)
        @creds_provider = options[:creds_provider]
        @app = app
      end

      def call(env)
        request = Rack::Request.new env
        request.params # contains the union of GET and POST params
        # request.xhr?   # requested with AJAX
        body = request.body   # the incoming request IO stream
      end
    end
  end
end

