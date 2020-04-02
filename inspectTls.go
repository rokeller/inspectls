package main

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log"
	"os"
)

func verifyCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	log.Printf("Found %d certificates.\n", len(rawCerts))

	for i := 0; i < len(rawCerts); i++ {
		rawCert := rawCerts[i]

		cert, err := x509.ParseCertificate(rawCert)

		if nil != err {
			log.Printf("Failed to parse certificate %d: %v\n", i, err)

			return err
		}

		log.Printf("Certificate %d:\n", i)
		log.Printf("  Subject        : %s\n", cert.Subject.CommonName)
		log.Printf("  DNS Names      : %v\n", cert.DNSNames)
		log.Printf("  Email Addresses: %v\n", cert.EmailAddresses)
		log.Printf("  Serial Number  : %v\n", cert.SerialNumber)

		sha1Thumbprint := sha1.Sum(cert.Raw)
		log.Printf("  SHA1 Thumbprint: %v\n", hex.EncodeToString(sha1Thumbprint[:]))

		log.Printf("  IP Addresses   : %v\n", cert.IPAddresses)
		log.Printf("  Not Before     : %v\n", cert.NotBefore)
		log.Printf("  Not After      : %v\n", cert.NotAfter)

	}

	return nil
}

func getTLSConfig() *tls.Config {
	config := tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyCert,
	}

	return &config
}

func main() {
	args := os.Args[1:]
	address := args[0]

	// Connect to the remote TLS server.
	conn, err := tls.Dial("tcp", address, getTLSConfig())

	if nil != err {
		panic(err)
	}

	if nil != err {
		log.Fatal(err)
	}

	conn.Close()
}
