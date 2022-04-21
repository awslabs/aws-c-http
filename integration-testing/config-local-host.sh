#!/usr/bin/env bash
set -e

sudo nginx -t

#Generate local ssl cert
openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

# copy config to etc/nginx/
sudo mv localhost.key localhost.crt /etc/nginx/

# copy the njs script
sudo mv ./integration-testing/njs /etc/nginx/

# overwrite the njs configuration
sudo mv -f ./integration-testing/nginx.conf /etc/nginx/

sudo systemctl start nginx

curl -k https://localhost:443/echo
