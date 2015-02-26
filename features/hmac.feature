Feature: Message signing functionality

  Scenario: Sign a bare-bones GET request
    Given the endpoint "GET" "/resource/1?key=value"
  	When I sign the request with the "SHA-1" digest and secret key "secret-key"
    Then I should see the signature "7Tq3+JP3lAu4FoJz81XEx5+qfOc="

  Scenario: Sign a complete POST request
  	Given the endpoint "POST" "/resource/1?key=value"
  	  And the header "Content-Type" "text/plain"
  	  And the header "Date" "Fri, 19 Mar 1982 00:00:04 GMT"
  	  And the custom header "Custom1" "Value1"
  	  And the body "test content"
  	When I sign the request with the "SHA-1" digest and secret key "secret-key"
  	Then I should see the signature "QRMtvnGmlP1YbaTwpWyB/6A8dRU="
