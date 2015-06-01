#!/bin/bash

HFILE=$(mktemp /tmp/headers.XXXXXX)

HMAC_KEY=$(echo -n "Y3VybHRlc3RrZXlfNzY0MWM3NTgtMDViMi00ZTIzLWJkMDktMWYwZDU3NTk0ZDhj" | openssl base64 -d -A)

get_nonce() {
  if [ -n "$(which uuidgen)" ]; then
    # On BSD systems, an uppercase uuid is returned
    uuidgen | tr 'ABCDEF' 'abcdef'
  else
    ruby -e "require 'securerandom'; print SecureRandom.uuid"
  fi
}

# Parameters:
# - http method
# - path
# - query string
# - JSON body
check_request() {

  HOST=localhost:8010
  METHOD="$1"
  PATH_INFO="$2"
  QUERY_STRING="$3"
  ID=curltest
  REALM=Test
  NONCE=$(get_nonce)
  TIME=$(date +%s)

  STRING_TO_SIGN=\
"$METHOD
$HOST
$PATH_INFO
$QUERY_STRING
id=${ID}&nonce=${NONCE}&realm=${REALM}&version=2.0
$TIME"

  # Optional body
  if [ "$METHOD" != "GET" ]; then
    SHA256=$(echo -n "$4" | openssl dgst -sha256 -binary | openssl base64 -A)
    STRING_TO_SIGN=${STRING_TO_SIGN}$(printf "\n%s\n%s" "application/json" "$SHA256")
  fi

  SIGNATURE=$(echo -n "$STRING_TO_SIGN" | openssl dgst -sha256 -hmac "$HMAC_KEY" -binary | openssl base64 -A)

  # Construct the authorization header
  AUTHORIZATION="Authorization: acquia-http-hmac realm=\"${REALM}\",id=\"${ID}\",nonce=\"${NONCE}\",version=\"2.0\",headers=\"\",signature=\"${SIGNATURE}\""

  if [ "$METHOD" != "GET" ]; then
    BODY=$(curl -s -X$METHOD "http://${HOST}${PATH_INFO}?${QUERY_STRING}" -H "$AUTHORIZATION" -H "X-Authorization-timestamp: ${TIME}" -H "X-Authorization-Content-SHA256: $SHA256" -H 'Content-Type: application/json' --data-binary "$4" -D $HFILE)
  else
    BODY=$(curl -s -X$METHOD "http://${HOST}${PATH_INFO}?${QUERY_STRING}" -H "$AUTHORIZATION" -H "X-Authorization-timestamp: ${TIME}" -D $HFILE)
  fi

  CODE=$(awk '$0 ~ "^HTTP/" { print $2 }' $HFILE)

  # Header lines have trailing \r
  RESP_SIGNATURE=$(awk '$0 ~ "^X-Server-Authorization-Hmac-Sha256:" { print $2 }' $HFILE | tr -d '\r')

  VERIFY_SIGNATURE=$(printf "%s\n%s\n%s" "$NONCE" "$TIME" "$BODY" | openssl dgst -sha256 -hmac "$HMAC_KEY" -binary | openssl base64 -A)

  rm $HFILE

  if [ "$CODE" != "200" -a "$CODE" != "201" ]; then
    echo "Non-20x response: $CODE"
    echo "$BODY"
    exit 1
  fi

  if [ "$VERIFY_SIGNATURE" != "$RESP_SIGNATURE" ]; then
    echo "Response signature mismatch"
    echo "$BODY"
    echo "$RESP_SIGNATURE"
    echo "$VERIFY_SIGNATURE"
    exit 1
  fi

  echo "Success: $BODY"
}

check_request "POST" "/hello" "" '{"hello":"from curl","params":["5","4","8"]}'
check_request "GET" "/hello" ""
check_request "GET" "/hello" "test=me&uuu=kkk"

