#!/bin/bash

set -e
set -x

echo "elasticurl binary is located at $1"

$1 -v TRACE example.com
$1 -v TRACE -P -H "content-type: application/json" -i -d "{'test':'testval'}" http://httpbin.org/post
$1 -v TRACE -o elastigirl.png https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png
curl https://s3.amazonaws.com/code-sharing-aws-crt/elastigirl.png --output elastigirl_curl.png

ELASTICURL_DL_SHA=($(sha1sum elastigirl.png))
CURL_DL_SHA=($(sha1sum elastigirl_curl.png))

if [ "$ELASTICURL_DL_SHA" == "$CURL_DL_SHA" ]; then
    echo "Downloads look good!"
    exit 0
fi

exit -1
    
