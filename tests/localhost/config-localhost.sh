#!/usr/bin/env bash
set -ex

# nginx source
curl -OL http://nginx.org/download/nginx-1.21.6.tar.gz
mv nginx-1.21.6.tar.gz /tmp/nginx-1.21.6.tar.gz # for the path to check
tar -xvzf /tmp/nginx-1.21.6.tar.gz

# openssl source
git clone -b openssl-3.0.2 https://github.com/openssl/openssl.git

# njs source
git clone -b 0.7.3 https://github.com/nginx/njs.git

# PCRE lib
curl -OL https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
tar xvzf pcre-8.45.tar.gz

# zlib
curl -OL https://www.zlib.net/zlib-1.2.12.tar.gz
tar xvzf zlib-1.2.12.tar.gz

# configure and build
cd nginx-1.21.6
mkdir nginx
./configure --add-dynamic-module=../njs/nginx --add-dynamic-module=../echo-nginx-module --with-openssl=../openssl --with-http_ssl_module --with-http_v2_module --prefix=./nginx --with-pcre=../pcre-8.45/ --with-zlib=../zlib-1.2.12

time make --jobs=`getconf _NPROCESSORS_ONLN`
sudo make install

#Generate local ssl cert
openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

# copy config to etc/nginx/
sudo cp localhost.key localhost.crt ./nginx/conf/

# copy the njs script
sudo cp -r ../tests/localhost/njs ./nginx/conf/

# overwrite the njs configuration
sudo cp ../tests/localhost/nginx.conf ./nginx/conf/

# check if the config works
sudo ./nginx/sbin/nginx -t

# start server
sudo ./nginx/sbin/nginx

# use curl to test if the server works
curl -v -k https://localhost:443/echo
