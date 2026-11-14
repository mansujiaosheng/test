package main

// Control experiment: what does Go's crypto/tls emit in a TLS1.3
// CertificateRequest, and which alert does it send when client-auth chain
// verification fails / when the client sends no certificate?
//
// Run a server with RequireAndVerifyClientCert and compare against
// 10.230.164.3:8443, which emits 5 extensions in CertificateRequest and
// alert 48 (unknown_ca).

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("srv.crt", "srv.key")
	if err != nil {
		log.Fatal("load keypair: ", err)
	}
	caPEM, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal("read ca: ", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("bad ca pem")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:19999", cfg)
	if err != nil {
		log.Fatal("listen: ", err)
	}
	log.Println("gostack reference server listening on 127.0.0.1:19999")

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Println("accept: ", err)
			continue
		}
		go func(conn interface{ Close() error }) {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn.(io.Reader))
		}(c)
	}
}
