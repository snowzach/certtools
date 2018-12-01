# CertTools

[![GoDoc Widget]][GoDoc]

CertTools is a set of settings and tools for TLS Certificates.

It includes parsers for taking strings/config options and enabling minimum TLS versions and Cipher Suites.
It also includes some decent static defaults which can be used when creating a server.
```
import (
    "github.com/snowzach/certtools/autocert"
    "github.com/snowzach/certtools"
)

// Generate a self-signed certificate for localhost using static string as private key data (repeatable)
// This programatically generates the same certificate every time and is only for development use
cert, err = autocert.New(autocert.InsecureStringReader("static string"))

// Build an http server using our self-signed cert and decent security ciphers and versions
server := &http.Server{
    Addr: ":8443",
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
```

CertTools can be used to programatically generate POTENTIALLY INSECURE certificates that can be used for your web server.
It's horribly insecure and is designed basically for the situation where you don't want to mess with cert files, you want 
to use tls/https and you don't want to have the cert be different every time you load your app.

[GoDoc]: https://godoc.org/github.com/snowzach/certtools
[GoDoc Widget]: https://godoc.org/github.com/snowzach/certtools?status.svg

