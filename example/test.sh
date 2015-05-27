#!/bin/bash

HFILE=$(mktemp /tmp/headers.XXXXXX)

HMAC_KEY=$(echo -n "Y3VybHRlc3RrZXlfNzY0MWM3NTgtMDViMi00ZTIzLWJkMDktMWYwZDU3NTk0ZDhj" | openssl base64 -d -A)

HOST=localhost:8010
METHOD=GET
PATH_INFO="/hello"
QUERY_STRING=""
ID=curltest
REALM=Test
# On BSD systems, an uppercase uuid is returned
NONCE=$(uuidgen | tr 'ABCDEF' 'abcdef')
TIME=$(date +%s)

STRING_TO_SIGN=\
"$METHOD
$HOST
$PATH_INFO
$QUERY_STRING
id=${ID}&nonce=${NONCE}&realm=${REALM}&version=2.0
$TIME"

SIGNATURE=$(echo -n "$STRING_TO_SIGN" | openssl dgst -sha256 -hmac "$HMAC_KEY" -binary | openssl base64 -A)

# Construct the authorization header
AUTHORIZATION="Authorization: acquia-http-hmac realm=\"${REALM}\",id=\"${ID}\",nonce=\"${NONCE}\",version=\"2.0\",headers=\"\",signature=\"${SIGNATURE}\""

BODY=$(curl -s -X$METHOD "http://${HOST}${PATH_INFO}?${QUERY_STRING}" -H "$AUTHORIZATION" -H "X-Acquia-timestamp: ${TIME}" -D $HFILE)

CODE=$(awk '$0 ~ "^HTTP/" { print $2 }' $HFILE)
# Header lines have trailing \r
RESP_SIGNATURE=$(awk '$0 ~ "^X-Acquia-Content-Hmac-Sha256:" { print $2 }' $HFILE | tr -d '\r')

VERIFY_SIGNATURE=$(printf "%s\n%s" "$NONCE" "$BODY" | openssl dgst -sha256 -hmac "$HMAC_KEY" -binary | openssl base64 -A)

rm $HFILE

if [ "$CODE" != "200" ]; then
  echo "Non-200 response: $CODE"
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
