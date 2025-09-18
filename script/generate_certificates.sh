#!/bin/bash
# Copyright (c) 2025 JAMF Software, LLC
set -e

PASS=cert/pass.txt
CA_CNF=cert/simple_network_relay_ca.cnf
ROOT_CA_CERT=cert/simple_network_relay_root_ca.crt
ROOT_CA_KEY=cert/simple_network_relay_root_ca.key
INTERMEDIATE_CA_CERT=cert/simple_network_relay_intermediate_ca.crt
INTERMEDIATE_CA_KEY=cert/simple_network_relay_intermediate_ca.key
INTERMEDIATE_CA_CSR=cert/simple_network_relay_intermediate_ca.csr
LEAF_CERT=cert/simple_network_relay.crt
LEAF_KEY=cert/simple_network_relay.key
LEAF_CSR=cert/simple_network_relay.csr
LEAF_CNF=cert/simple_network_relay_leaf.cnf

generate_password() {
  [ -f ${PASS} ] && return
  LC_ALL=C tr -dc 'a-zA-Z' < /dev/urandom | head -c 12 > ${PASS}
}

generate_ca_cnf() {
  cat > "${CA_CNF}" << EOF
[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

[ req_distinguished_name ]
commonName                      = Common Name
emailAddress                    = Email Address

default_md          = sha256
x509_extensions     = v3_ca

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
}

generate_leaf_cnf() {
  HOST=$(scutil --get LocalHostName || hostname)
  [[ $HOST != *.local ]] && HOST="${HOST}.local"
  cat > "${LEAF_CNF}" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN=${HOST}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOST}
IP.1 = 127.0.0.1
EOF
}

generate_root_ca() {
  [ -f ${ROOT_CA_CERT} ] && return
  openssl genrsa -aes256 -passout file:${PASS} -out ${ROOT_CA_KEY} 4096
  openssl req -config ${CA_CNF} -subj "/CN=Simple Network Relay Root CA" -key ${ROOT_CA_KEY} -new -x509 -sha512 -days 7300 -extensions v3_ca -out ${ROOT_CA_CERT} -passin file:${PASS}
  openssl x509 -noout -text -in ${ROOT_CA_CERT} | head
}

generate_intermediate_ca() {
  [ -f ${INTERMEDIATE_CA_KEY} ] && return
  openssl genrsa -aes256 -passout file:${PASS} -out ${INTERMEDIATE_CA_KEY} 2048
  openssl req -config ${CA_CNF} -new \
    -subj "/CN=Simple Network Relay Intermediate CA" \
    -key ${INTERMEDIATE_CA_KEY} \
    -out ${INTERMEDIATE_CA_CSR} \
    -passin file:${PASS}
  openssl x509 -req -CAcreateserial -sha256 -days 365 -extfile ${CA_CNF} -extensions v3_intermediate_ca -CA ${ROOT_CA_CERT} -CAkey ${ROOT_CA_KEY} -in ${INTERMEDIATE_CA_CSR} -out ${INTERMEDIATE_CA_CERT} -passin file:${PASS}
  openssl x509 -noout -text -in ${INTERMEDIATE_CA_CERT} | head
  openssl verify -CAfile ${ROOT_CA_CERT} ${INTERMEDIATE_CA_CERT}
}

generate_leaf() {
  [ -f ${LEAF_CERT} ] && return
  openssl genpkey -algorithm RSA -out ${LEAF_KEY}
  openssl req -new -key ${LEAF_KEY} -out ${LEAF_CSR} -config ${LEAF_CNF}
  openssl x509 -req -days 365 -in ${LEAF_CSR} -CA ${INTERMEDIATE_CA_CERT} -CAkey ${INTERMEDIATE_CA_KEY} -CAcreateserial -extfile ${LEAF_CNF} -extensions req_ext -out ${LEAF_CERT} -passin file:${PASS}
  rm ${LEAF_CSR}
  cat ${INTERMEDIATE_CA_CERT} >> ${LEAF_CERT}
}

[ -d cert ] || mkdir cert
generate_password
generate_ca_cnf
generate_root_ca
generate_intermediate_ca
generate_leaf_cnf
generate_leaf
