# CertTools

[![GoDoc Widget]][GoDoc]

CertTools is a set of settings and tools for TLS Certificates.

It includes parsers for taking strings/config options and enabling minimum TLS versions and Cipher Suites.
It also includes some decent static defaults which can be used when creating a server.
```
server := &http.Server{
    Addr: ":8443",
    Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        w.Header().Set("Content-Type", "text/plain")
        w.Write([]byte("This is an example server.\n"))
    }),
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   autocert.SecureTLSMinVersion(),
        CipherSuites: autocert.SecureTLSCipherSuites(),
    },
}
```

CertTools can be used to programatically generate POTENTIALLY INSECURE certificates that can be used for your web server.
It's horribly insecure and is designed basically for the situation where you don't want to mess with cert files, you want 
to use tls/https and you don't want to have the cert be different every time you load your app.
