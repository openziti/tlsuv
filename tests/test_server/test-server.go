package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"net/http"
	"strconv"
)

func runHTTP(port int, handler http.Handler) chan error {
	done := make(chan error)
	go func() {
		done <- http.ListenAndServe(":"+strconv.Itoa(port), handler)
	}()
	return done
}

func runHTTPS(port int, handler http.Handler, keyFile, certFile string) chan error {
	done := make(chan error)
	go func() {
		done <- http.ListenAndServeTLS(":"+strconv.Itoa(port), certFile, keyFile, handler)
	}()
	return done
}

type authHandler struct {
}

func (a authHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	certs := request.TLS.PeerCertificates
	if len(certs) == 0 {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("I don't know you"))
	} else {
		_, _ = writer.Write([]byte("you are '" + certs[0].Subject.String() + "' by " + certs[0].Issuer.String()))
	}
}

func runClientAuth(port int, keyFile, certFile string) chan error {
	done := make(chan error)
	server := http.Server{
		Handler: new(authHandler),
		Addr:    fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		}}

	go func() {
		done <- server.ListenAndServeTLS(certFile, keyFile)
	}()
	return done
}

func runEchoServer(port int, keyFile, certFile string) chan error {
	done := make(chan error)
	cfg := &tls.Config{}
	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	cfg.Certificates = append(cfg.Certificates, cert)

	go func() {
		server, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), cfg)
		if err != nil {
			done <- err
			return
		}

		for {
			clt, err := server.Accept()
			if err != nil {
				done <- err
				return
			}

			go func() {
				for {
					buf := make([]byte, 1024)
					n, err := clt.Read(buf)
					if err != nil {
						return
					}
					if wc, err := clt.Write(buf[:n]); err != nil || wc != n {
						return
					}
				}
			}()
		}
	}()
	return done
}

var keyFile string
var certFile string

func init() {
	flag.StringVar(&keyFile, "keyfile", "", "key file for HTTPS listener")
	flag.StringVar(&certFile, "certfile", "", "cert file for HTTPS listener")
	flag.Parse()
}

func main() {
	httpb := httpbin.New()

	var err error
	select {
	case err = <-runHTTP(8080, httpb):
	case err = <-runHTTPS(8443, httpb, keyFile, certFile):
	case err = <-runClientAuth(9443, keyFile, certFile):
	case err = <-runEchoServer(7443, keyFile, certFile):
	}

	fmt.Println(err)
}
