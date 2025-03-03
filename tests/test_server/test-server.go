package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func runHTTP(port int, handler http.Handler) chan error {
	done := make(chan error)
	go func() {
		done <- http.ListenAndServe("127.0.0.1:"+strconv.Itoa(port), handler)
	}()
	return done
}

func runHTTPS(port int, handler http.Handler) chan error {
	done := make(chan error)
	server := http.Server{
		Handler: handler,
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequestClientCert,
		}}

	go func() {
		done <- server.ListenAndServeTLS("", "")
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

func runClientAuth(port int) chan error {
	done := make(chan error)
	server := http.Server{
		Handler: new(authHandler),
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequestClientCert,
		}}

	go func() {
		done <- server.ListenAndServeTLS("", "")
	}()
	return done
}

func runEchoServer(port int) chan error {
	done := make(chan error)
	cfg := &tls.Config{}
	cfg.Certificates = append(cfg.Certificates, serverCert)

	go func() {
		server, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
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
				defer func(clt net.Conn) {
					_ = clt.Close()
				}(clt)

				buf := make([]byte, 1024)
				for {
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

var serverCert tls.Certificate

func init() {
	var ca string
	var caKey string

	flag.StringVar(&ca, "ca", "", "CA certificate")
	flag.StringVar(&caKey, "ca-key", "", "CA private key")
	flag.Parse()

	caCert, err := tls.LoadX509KeyPair(ca, caKey)
	if err != nil {
		panic(err)
	}
	caX509, _ := x509.ParseCertificate(caCert.Certificate[0])

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	templ := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"OpenZiti"},
			CommonName:   "Test Server",
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
	}
	templ.SerialNumber = big.NewInt(42)
	serverX509, err := x509.CreateCertificate(rand.Reader, templ, caX509, serverKey.Public(), caCert.PrivateKey)
	if err != nil {
		panic(err)
	}

	serverCert = tls.Certificate{
		PrivateKey: serverKey,
	}
	serverCert.Certificate = append(serverCert.Certificate, serverX509)
}

func runProxy(port int) chan error {
	done := make(chan error)
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.KeepHeader = true
	proxy.KeepDestinationHeaders = true
	go func() {
		done <- http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), proxy)
	}()
	return done
}

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	httpb := httpbin.New(
		func(httpBin *httpbin.HTTPBin) {
			httpBin.Observer = func(result httpbin.Result) {
				log.Print(result)
			}
		})

	var err any
	select {
	case err = <-runHTTP(8080, httpb):
	case err = <-runHTTPS(8443, httpb):
	case err = <-runClientAuth(9443):
	case err = <-runEchoServer(7443):
	case err = <-runProxy(13128):
	case err = <-sigs:
	}

	if err != nil {
		fmt.Println(err)
	}
}
