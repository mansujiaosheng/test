// Stock Go mTLS server used to validate the alert-mapping inference for T02.
// Config mirrors what 10.230.164.3:8443 behaves like:
//   TLS1.3 only, RequireAndVerifyClientCert, ClientCAs = one root.
// Run: go run lab_server.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	cert, err := tls.LoadX509KeyPair("srv.pem", "srv.key")
	if err != nil {
		log.Fatal(err)
	}
	pem, err := os.ReadFile("root.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Fatal("bad root pem")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			fmt.Fprintf(w, "ok peer=%s\n", r.TLS.PeerCertificates[0].Subject.CommonName)
			return
		}
		fmt.Fprintln(w, "ok no-peer")
	})
	srv := &http.Server{
		Addr: "127.0.0.1:9443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS13,
		},
	}
	log.Printf("listening 127.0.0.1:9443, go=%s", "1.24")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
