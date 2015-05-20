require 'bundler/setup'
require 'grape'
require 'json'

module Example
  class App < Grape::API
    version 'v1', using: :header, vendor: 'acquia'

    content_type :json, 'application/json'
    format :json
    default_format :json

    get '/hello' do
      out = {hello: "world"}
      params.each do |k,v|
        out[k] = v
      end
      out
    end
  end
end
