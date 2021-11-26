require 'minitest/autorun'
require_relative '../lib/acquia-http-hmac'

class TestAcquiaHmacSpec < Minitest::Test

  def test_fixture
    fixtures_path = File.join(File.dirname(__FILE__), '../fixtures/acquia_spec.json')
    fixtures_json = File.read(File.realpath(fixtures_path))
    fixtures = JSON.parse(fixtures_json)

    fixtures['fixtures']['2.0'].each do |fixture|
      input = fixture['input']
      expectations = fixture['expectations']
      uri = URI(input['url'])
      signed_headers = {}
      input['signed_headers'].each do |signed_header|
        signed_headers[signed_header] = input['headers'][signed_header]
      end
      body = input['content_body'].empty? ? nil : input['content_body']
      body_hash = input['content_sha'].empty? ? nil : input['content_sha']
      mac = Acquia::HTTPHmac::Auth.new(input['realm'], input['secret'])
      args = {
        http_method: input['method'],
        host: input['host'],
        id: input['id'],
        path_info: uri.path,
        query_string: uri.query,
        body: body,
        content_type: input['content_type'],
        nonce: input['nonce'],
        timestamp: input['timestamp'],
        headers: signed_headers,
        body_hash: body_hash,
      }
      headers = mac.prepare_request_headers(args)

      # Prove we can generate the correct Authorization header.
      expected_realm = Addressable::URI.escape(input['realm'])
      assert(headers['Authorization'].include?("realm=\"#{expected_realm}\""))
      assert(headers['Authorization'].include?("id=\"#{input['id']}\""))
      assert(headers['Authorization'].include?("nonce=\"#{input['nonce']}\""))
      expected_headers = input['signed_headers'].join(';')
      assert(headers['Authorization'].include?("headers=\"#{expected_headers}\""))
      assert(headers['Authorization'].include?("version=\"2.0\""))
      assert(headers['Authorization'].include?("signature=\"#{expectations['message_signature']}\""))

      # Prove that we can authenticate the request.
      attributes = Acquia::HTTPHmac::Auth::parse_auth_header(expectations['authorization_header'])
      auth_args = args.merge(attributes)
      auth_args[:allowed_skew] = input['timestamp'] + 900
      auth_args[:headers] = signed_headers
      ret = mac.request_authenticated?(auth_args)
      assert(ret, "request_authenticated? failed for #{input['name']}")
    end

  end

end
