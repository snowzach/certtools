package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/snowzach/certtools"
	"github.com/snowzach/certtools/autocert"
)

func main() {

	// Get the hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}

	address := flag.String("l", ":1234", "What address to listen on")
	cn := flag.String("cn", hostname, "The common name for the certificate")
	o := flag.String("o", "", "The org for the certificate")
	ou := flag.String("ou", "", "The org unit for the certificate")
	flag.Parse()

	uri, _ := url.Parse("https://" + hostname)

	// Good starting at unix epoch for 100 years
	var notBefore = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	var notAfter time.Time = notBefore.Add(100 * 365 * 24 * time.Hour)

	// This will generate the same certificate every time it is run on the same host
	cert, err := autocert.New(autocert.InsecureStringReader(hostname),
		autocert.SerialNumber(1),
		autocert.CommonName(*cn),
		autocert.Organization([]string{*o}),
		autocert.OrganizationalUnit([]string{*ou}),
		autocert.URIs([]*url.URL{uri}),
		autocert.DNSNames([]string{hostname}),
		autocert.ValidTimes(notBefore, notAfter),
	)

	// Build the server and manually specify TLS Config
	server := &http.Server{
		Addr: *address,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("This is an example server.\n"))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   certtools.SecureTLSMinVersion(),
			CipherSuites: certtools.SecureTLSCipherSuites(),
		},
	}

	// Listen
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Listening on %s\n", *address)

	// Serve
	if err := server.Serve(tls.NewListener(listener, server.TLSConfig)); err != nil {
		panic(err)
	}

}
