#/bin/sh

mkdir -p /etc/httpd/conf/ssl.crt
mkdir -p /etc/httpd/conf/ssl.csr
mkdir -p /etc/httpd/conf/ssl.key

echo -e "[ req ]
distinguished_name     = req_distinguished_name
prompt                 = no

[ req_distinguished_name ]
C                      = FR
ST                     = None
L                      = Paris
O                      = COMVERSE
OU                     = Netcentrex
CN                     = OpenKVI 
emailAddress           = OpenKVI@comverse.com" > /tmp/config_ssl

openssl genrsa -rand /var/log/messages -out /etc/httpd/conf/ssl.key/openkvi_server.key 2048

openssl req -new \
-config /tmp/config_ssl \
-newkey rsa:2048 \
-keyout /etc/httpd/conf/ssl.key/openkvi_server.key \
-nodes \
-days 3650 \
-x509 \
-out /etc/httpd/conf/ssl.crt/openkvi_server.crt

