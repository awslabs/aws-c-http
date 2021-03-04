#!/bin/bash

set -e

if test -f "/tmp/setup_proxy_test_env.sh"; then
    source /tmp/setup_proxy_test_env.sh
    env
    curl --verbose --proxy http://ec2-100-25-139-228.compute-1.amazonaws.com:3128 www.example.com
fi

python3 -c "from urllib.request import urlretrieve; urlretrieve('https://d19elf31gohf1l.cloudfront.net/LATEST/builder.pyz?date=`date +%s`', 'builder')"
chmod a+x builder
./builder build -p aws-c-http $*
