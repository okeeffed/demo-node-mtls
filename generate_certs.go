package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// Create directory for certs
	os.MkdirAll("certs", 0755)

	// Generate Root CA
	rootKey, rootCert := createRootCA()

	// Generate Intermediate CA
	intermediateKey, intermediateCert := createIntermediateCA(rootKey, rootCert)

	// Generate Server certificate
	createServerCertificate(intermediateKey, intermediateCert)

	// Generate Client certificate
	createClientCertificate(intermediateKey, intermediateCert)

	// Create CA chain for verification
	createCAChain(rootCert, intermediateCert)

	log.Println("Certificate generation complete!")
}

func createRootCA() (*rsa.PrivateKey, *x509.Certificate) {
	// Generate private key
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate root private key: %v", err)
	}

	// Save private key
	savePrivateKey(rootKey, "certs/rootCA.key")

	// Prepare certificate template
	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MyRootCA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2, // Allow up to intermediate CA + leaf
	}

	// Self-sign the root certificate
	rootCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&rootTemplate,
		&rootTemplate,
		&rootKey.PublicKey,
		rootKey,
	)
	if err != nil {
		log.Fatalf("Failed to create root certificate: %v", err)
	}

	// Save certificate
	saveCertificate(rootCertDER, "certs/rootCA.crt")

	// Parse and return the certificate for later use
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		log.Fatalf("Failed to parse root certificate: %v", err)
	}

	log.Println("Root CA created successfully")
	return rootKey, rootCert
}

func createIntermediateCA(rootKey *rsa.PrivateKey, rootCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	// Generate private key
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate intermediate private key: %v", err)
	}

	// Save private key
	savePrivateKey(intermediateKey, "certs/intermediateCA.key")

	// Prepare certificate template
	intermediateTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "MyIntermediateCA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // 5 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // No further CAs allowed below this
	}

	// Sign with root CA
	intermediateCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&intermediateTemplate,
		rootCert,
		&intermediateKey.PublicKey,
		rootKey,
	)
	if err != nil {
		log.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	// Save certificate
	saveCertificate(intermediateCertDER, "certs/intermediateCA.crt")

	// Parse and return the certificate for later use
	intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
	if err != nil {
		log.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	log.Println("Intermediate CA created successfully")
	return intermediateKey, intermediateCert
}

func createServerCertificate(intermediateKey *rsa.PrivateKey, intermediateCert *x509.Certificate) {
	// Generate private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate server private key: %v", err)
	}

	// Save private key
	savePrivateKey(serverKey, "certs/server.key")

	// Prepare certificate template
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0), // 2 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Sign with intermediate CA
	serverCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		intermediateCert,
		&serverKey.PublicKey,
		intermediateKey,
	)
	if err != nil {
		log.Fatalf("Failed to create server certificate: %v", err)
	}

	// Save certificate
	saveCertificate(serverCertDER, "certs/server.crt")

	// Create server chain
	createServerChain()

	log.Println("Server certificate created successfully")
}

func createClientCertificate(intermediateKey *rsa.PrivateKey, intermediateCert *x509.Certificate) {
	// Generate private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate client private key: %v", err)
	}

	// Save private key
	savePrivateKey(clientKey, "certs/client.key")

	// Prepare certificate template
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(2, 0, 0), // 2 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Sign with intermediate CA
	clientCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&clientTemplate,
		intermediateCert,
		&clientKey.PublicKey,
		intermediateKey,
	)
	if err != nil {
		log.Fatalf("Failed to create client certificate: %v", err)
	}

	// Save certificate
	saveCertificate(clientCertDER, "certs/client.crt")

	// Create client chain
	createClientChain()

	log.Println("Client certificate created successfully")
}

func savePrivateKey(privateKey *rsa.PrivateKey, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create private key file %s: %v", filename, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		log.Fatalf("Failed to write private key to %s: %v", filename, err)
	}
}

func saveCertificate(derBytes []byte, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create certificate file %s: %v", filename, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	if err != nil {
		log.Fatalf("Failed to write certificate to %s: %v", filename, err)
	}
}

func createServerChain() {
	serverCert, err := os.ReadFile("certs/server.crt")
	if err != nil {
		log.Fatalf("Failed to read server certificate: %v", err)
	}

	intermediateCert, err := os.ReadFile("certs/intermediateCA.crt")
	if err != nil {
		log.Fatalf("Failed to read intermediate certificate: %v", err)
	}

	chainFile, err := os.Create("certs/server-chain.crt")
	if err != nil {
		log.Fatalf("Failed to create server chain file: %v", err)
	}
	defer chainFile.Close()

	_, err = chainFile.Write(serverCert)
	if err != nil {
		log.Fatalf("Failed to write server cert to chain file: %v", err)
	}

	_, err = chainFile.Write(intermediateCert)
	if err != nil {
		log.Fatalf("Failed to write intermediate cert to chain file: %v", err)
	}
}

func createClientChain() {
	clientCert, err := os.ReadFile("certs/client.crt")
	if err != nil {
		log.Fatalf("Failed to read client certificate: %v", err)
	}

	intermediateCert, err := os.ReadFile("certs/intermediateCA.crt")
	if err != nil {
		log.Fatalf("Failed to read intermediate certificate: %v", err)
	}

	chainFile, err := os.Create("certs/client-chain.crt")
	if err != nil {
		log.Fatalf("Failed to create client chain file: %v", err)
	}
	defer chainFile.Close()

	_, err = chainFile.Write(clientCert)
	if err != nil {
		log.Fatalf("Failed to write client cert to chain file: %v", err)
	}

	_, err = chainFile.Write(intermediateCert)
	if err != nil {
		log.Fatalf("Failed to write intermediate cert to chain file: %v", err)
	}
}

func createCAChain(rootCert *x509.Certificate, intermediateCert *x509.Certificate) {
	rootCertPEM, err := os.ReadFile("certs/rootCA.crt")
	if err != nil {
		log.Fatalf("Failed to read root certificate: %v", err)
	}

	intermediateCertPEM, err := os.ReadFile("certs/intermediateCA.crt")
	if err != nil {
		log.Fatalf("Failed to read intermediate certificate: %v", err)
	}

	caChainFile, err := os.Create("certs/ca-chain.crt")
	if err != nil {
		log.Fatalf("Failed to create CA chain file: %v", err)
	}
	defer caChainFile.Close()

	_, err = caChainFile.Write(rootCertPEM)
	if err != nil {
		log.Fatalf("Failed to write root cert to CA chain file: %v", err)
	}

	_, err = caChainFile.Write(intermediateCertPEM)
	if err != nil {
		log.Fatalf("Failed to write intermediate cert to CA chain file: %v", err)
	}
}
