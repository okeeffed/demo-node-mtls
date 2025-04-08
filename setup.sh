#!/bin/bash

# Create directories for better organization
mkdir -p certs

# Root private key
openssl genrsa -out certs/rootCA.key 4096

# Root self-signed certificate
openssl req -x509 -new -nodes -key certs/rootCA.key -sha256 -days 3650 \
  -subj "/CN=MyRootCA" -out certs/rootCA.crt

# Intermediate CA config
cat > intermediate-ext.cnf <<EOF
[ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# Intermediate CA private key
openssl genrsa -out certs/intermediateCA.key 4096

# Intermediate CSR
openssl req -new -key certs/intermediateCA.key -out certs/intermediateCA.csr \
  -subj "/CN=MyIntermediateCA"

# Use Root CA to sign the intermediate's CSR
openssl x509 -req -in certs/intermediateCA.csr -CA certs/rootCA.crt -CAkey certs/rootCA.key \
  -CAcreateserial -out certs/intermediateCA.crt -days 1825 -sha256 \
  -extfile intermediate-ext.cnf -extensions ext

# Server config
cat > server-ext.cnf <<EOF
[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
EOF

# Server private key
openssl genrsa -out certs/server.key 2048

# Server CSR
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/CN=localhost"

# Sign with intermediate CA
openssl x509 -req -in certs/server.csr -CA certs/intermediateCA.crt -CAkey certs/intermediateCA.key \
  -CAcreateserial -out certs/server.crt -days 825 -sha256 \
  -extfile server-ext.cnf -extensions ext

# Client config
cat > client-ext.cnf <<EOF
[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Client private key
openssl genrsa -out certs/client.key 2048

# Client CSR
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/CN=client"

# Sign with intermediate CA
openssl x509 -req -in certs/client.csr -CA certs/intermediateCA.crt -CAkey certs/intermediateCA.key \
  -CAcreateserial -out certs/client.crt -days 825 -sha256 \
  -extfile client-ext.cnf -extensions ext

# Concatenation of certificates
cat certs/server.crt certs/intermediateCA.crt > certs/server-chain.crt
cat certs/client.crt certs/intermediateCA.crt > certs/client-chain.crt

# Create a full CA chain file for verification
cat certs/rootCA.crt certs/intermediateCA.crt > certs/ca-chain.crt

# Verify the certificates with the full CA chain
echo "Verifying server certificate..."
openssl verify -CAfile certs/ca-chain.crt certs/server.crt

echo "Verifying client certificate..."
openssl verify -CAfile certs/ca-chain.crt certs/client.crt

# Display certificate information
echo "Server certificate info:"
openssl x509 -in certs/server.crt -text -noout | grep -E "Subject:|Issuer:|X509v3 Extended Key Usage:"

echo "Client certificate info:"
openssl x509 -in certs/client.crt -text -noout | grep -E "Subject:|Issuer:|X509v3 Extended Key Usage:"

echo "Certificate generation complete!"
