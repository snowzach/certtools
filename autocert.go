package certtools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

// InsecureGlobalStatic is a non-random byte reader that can be used to generaate an insecure private key
// This will generate the same bytes on every box (all zeros). It is horribly insecure.
type InsecureGlobalStatic struct{}

func InsecureGlobalStaticReader() InsecureGlobalStatic {
	return InsecureGlobalStatic{}
}

func (r InsecureGlobalStatic) Read(s []byte) (int, error) {
	// Set it to all zeros
	l := len(s)
	for x := 0; x < l; x++ {
		s[x] = 0
	}
	return l, nil
}

// InsecureString is a non-random bytes reader that can be used to generate an insecure private key based on a provided string
// The upside of this is that the same string input should yield the same bytes so you can send in something like the hostname
// and it will generate the same output everytime you run your program.
// The downside is that it is very insecure and should only be used for testing
type InsecureString struct {
	seed   []byte
	pos    int
	length int
}

func InsecureStringReader(seed string) *InsecureString {
	// Ensure there is at least one character in seed
	if len(seed) == 0 {
		seed = " "
	}
	return &InsecureString{
		seed:   []byte(seed),
		pos:    0,
		length: len(seed),
	}
}
func (r *InsecureString) Read(s []byte) (int, error) {
	// Just repead the string over and over
	l := len(s)
	for x := 0; x < l; x++ {
		s[x] = r.seed[r.pos%r.length]
		r.pos++
	}
	return l, nil
}

// AutoCert generates a self-signed cert using the specified private key mechanism
func AutoCert(commonName string, orgName string, orgUnitName string, dnsNames []string, notBefore time.Time, notAfter time.Time, keyReader io.Reader) (tls.Certificate, error) {

	if commonName == "" {
		return tls.Certificate{}, fmt.Errorf("commonName must not be blank")
	}

	// Generate the key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), keyReader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Could not generate private key: %v\n", err)
	}

	// Build Cert
	cert := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		IsCA: true,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
	}

	// If dnsNames is nil, use common name
	if dnsNames == nil {
		cert.DNSNames = []string{commonName}
	} else {
		cert.DNSNames = dnsNames
	}

	if orgName != "" {
		cert.Subject.Organization = []string{orgName}
	}
	if orgUnitName != "" {
		cert.Subject.OrganizationalUnit = []string{orgUnitName}
	}

	// Create Cert
	derBytes, err := x509.CreateCertificate(keyReader, &cert, &cert, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to create certificate: %s", err)
	}

	pKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to marshal private key: %s", err)
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pKeyBytes})

	tlsCert, err := tls.X509KeyPair(certBytes, privBytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Failed to load key-pair: %s", err)
	}

	return tlsCert, nil
}
