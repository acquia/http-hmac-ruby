require 'bundler/setup'
require 'securerandom'
require 'grape'
require 'json'

module Example
  class App < Grape::API
    version 'v1', using: :header, vendor: 'acquia'

    content_type :json, 'application/json'
    format :json
    default_format :json

    helpers do
      def hellos
        # Store data in memory for simple testing.
        @@hellos ||= {SecureRandom.uuid => "world"}
        @@hellos
      end
    end

    resource :hello do
      get do
        {hello: hellos}
      end

      desc "Return a single hello."
      get ':id' do
        {hello: hellos[params[:id]]}
      end

      params do
        requires :hello, type: String, desc: "A hello."
      end
      post do
        id = SecureRandom.uuid
        hellos[id] = params[:hello]
        {id => params[:hello]}
      end
    end
  end
end
