#!/usr/bin/env bash

openssl x509 -text < ca.pem | tee ca.txt
openssl x509 -text < cert.pem | tee cert.txt
openssl storeutl -noout -text -certs chain.pem | tee chain.txt
openssl ocsp -respin ./ocsp.der -text -issuer ca.pem -cert cert.pem | tee ocsp.txt

openssl pkcs12 -nodes -password pass:1234 < root-ca-test.p12 > root-ca-test.txt
