package autocert

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
	"net"
	"net/url"
	"time"
)

type AutoCertOption func(*x509.Certificate)

// AutoCert generates a self-signed cert using the specified keyReader for a source for private key generation
func New(keyReader io.Reader, opts ...AutoCertOption) (tls.Certificate, error) {

	// Generate the key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), keyReader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("Could not generate private key: %v\n", err)
	}

	// Build Cert
	cert := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "localhost",
		},

		// Starting jan 1, 2010 for 100 years
		NotBefore: time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC).Add(100 * 365 * 24 * time.Hour),

		IsCA: true,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
	}

	// Apply the options
	for _, f := range opts {
		f(&cert)
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

// SerialNummber sets the serial number for the cert
func SerialNumber(sn int64) AutoCertOption {
	return func(c *x509.Certificate) {
		c.SerialNumber = big.NewInt(sn)
	}
}

// CommonName sets the commont name of the certificate
func CommonName(cn string) AutoCertOption {
	return func(c *x509.Certificate) {
		c.Subject = pkix.Name{
			CommonName: cn,
		}
	}
}

// Organization sets the Organization(s) of the cert subject
func Organization(o []string) AutoCertOption {
	return func(c *x509.Certificate) {
		c.Subject.Organization = o
	}
}

// OrganizationalUnit sets the OrganizationalUnit(s) of the cert subject
func OrganizationalUnit(ou []string) AutoCertOption {
	return func(c *x509.Certificate) {
		c.Subject.OrganizationalUnit = ou
	}
}

// DNSNames sets the DNS names of the cert
func DNSNames(dnsNames []string) AutoCertOption {
	return func(c *x509.Certificate) {
		c.DNSNames = dnsNames
	}
}

// URIs sets the URIs of the cert
func URIs(uris []*url.URL) AutoCertOption {
	return func(c *x509.Certificate) {
		c.URIs = uris
	}
}

// IPAddresses sets the IPAddresses of the cert
func IPAddresses(ips []net.IP) AutoCertOption {
	return func(c *x509.Certificate) {
		c.IPAddresses = ips
	}
}

// ValidTimes sets the times in which this cert is valid
func ValidTimes(notBefore time.Time, notAfter time.Time) AutoCertOption {
	return func(c *x509.Certificate) {
		c.NotBefore = notBefore
		c.NotAfter = notAfter
	}
}
