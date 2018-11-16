package certtools

import (
	"crypto/tls"
	"fmt"
)

var (

	// tlsVersions is a string array of TLS versions suitable for use by tlsMinVersion
	tlsVersions = map[string]uint16{
		`VersionTLS10`: tls.VersionTLS10,
		`VersionTLS11`: tls.VersionTLS11,
		`VersionTLS12`: tls.VersionTLS12,
	}

	defaultTLSMinVersion uint16 = tls.VersionTLS12

	// tlsCipherSuites is a map of TLS CipherSuites from crypto/tls
	// Available CipherSuites defined at https://golang.org/pkg/crypto/tls/#pkg-constants
	tlsCipherSuites = map[string]uint16{
		`TLS_RSA_WITH_RC4_128_SHA`:                tls.TLS_RSA_WITH_RC4_128_SHA,
		`TLS_RSA_WITH_3DES_EDE_CBC_SHA`:           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		`TLS_RSA_WITH_AES_128_CBC_SHA`:            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		`TLS_RSA_WITH_AES_256_CBC_SHA`:            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		`TLS_RSA_WITH_AES_128_CBC_SHA256`:         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		`TLS_RSA_WITH_AES_128_GCM_SHA256`:         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		`TLS_RSA_WITH_AES_256_GCM_SHA384`:         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		`TLS_ECDHE_ECDSA_WITH_RC4_128_SHA`:        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		`TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`:    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		`TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`:    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		`TLS_ECDHE_RSA_WITH_RC4_128_SHA`:          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		`TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`:     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`:      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		`TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`:      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		`TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`:   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`:   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		`TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305`:    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`:  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	// defaultTLSCipherSuites is the A+ and A list of suites from: https://www.owasp.org/index.php/TLS_Cipher_String_Cheat_Sheet
	defaultTLSCipherSuites = []uint16{
		// These are compatible with grpc
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		// These are compatible with autocert
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	}
)

// SecureTLSMinVersion returns a secure TLSMinVersion=defaultTLSMinVersion
func SecureTLSMinVersion() uint16 {
	return defaultTLSMinVersion
}

// This takes a string TLS version and converts it into the go tls version. A blank version will return defaultTLSMinVersion
func ParseTLSVersion(version string) (uint16, error) {
	// Blank/Default value is tls.VersionTLS12
	if version == "" {
		return defaultTLSMinVersion, nil
	}
	// Otherwise parse values
	if value, ok := tlsVersions[version]; ok {
		return value, nil
	}
	return defaultTLSMinVersion, fmt.Errorf("Unknown tls version: %s", version)
}

// SecureTLSCipherSuites returns secure TLSCipherSuites=defaultTLSCipherSuites
func SecureTLSCipherSuites() []uint16 {
	return defaultTLSCipherSuites
}

// This parses a list of tlsCipherSuite strings and returns a slice of tls.CypherSuite values. Blank/Default = defaultTLSCipherSuites
func ParseTLSCipherSuites(suites []string) ([]uint16, error) {
	ret := make([]uint16, 0)

	// By default (nothing passed) enable all suites
	if len(suites) == 0 {
		return defaultTLSCipherSuites, nil
	} else {
		for _, suite := range suites {
			if value, ok := tlsCipherSuites[suite]; ok {
				ret = append(ret, value)
			} else {
				return nil, fmt.Errorf("Unknown tls cipher suite %s", suite)
			}
		}
	}

	return ret, nil
}
