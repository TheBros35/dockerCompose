#!/usr/bin/env bash

openssl req -x509 -out ../certs1/server1.crt -keyout ../certs1/server1.key \
  -newkey rsa:4096 -nodes -sha512 -days 365 \
  -subj '/CN=webnode1' -extensions EXT -config <( \
   printf "[dn]\nCN=webnode1\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:webnode1\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

openssl req -x509 -out ../certs2/server2.crt -keyout ../certs2/server2.key \
  -newkey rsa:4096 -nodes -sha512 -days 365 \
  -subj '/CN=webnode2' -extensions EXT -config <( \
   printf "[dn]\nCN=webnode2\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:webnode2\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

openssl req -x509 -out ../lb.crt -keyout ../lb.key \
  -newkey rsa:4096 -nodes -sha512 -days 365 \
  -subj '/CN=loadbalancer' -extensions EXT -config <( \
   printf "[dn]\nCN=loadbalancer\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:loadbalancer\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

cat ../lb.key ../lb.crt > ../lb.pem
mv ../lb.crt ../apache/lb.crt
mv ../lb.key ../apache/lb.key
