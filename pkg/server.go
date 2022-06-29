package transport

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

const (
	serverCertFilePath = "/Users/lethe/code/go/cert-http/cert/server.cer"
	serverKeyFilePath  = "/Users/lethe/code/go/cert-http/cert/server.key"
	rootCertFilePath   = "/Users/lethe/code/go/cert-http/cert/full_chain.cer"
)

func getTLSServerConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(serverCertFilePath, serverKeyFilePath)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	certBytes, err := ioutil.ReadFile(rootCertFilePath)
	if err != nil {
		panic("Unable to read cert.pem")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCertPool,
	}
	return config, nil
}

func RunTLSServer() {
	tlsConfig, err := getTLSServerConfig()
	if err != nil {
		log.Println(err)
		return
	}
	ln, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()
	log.Println("tls server running")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}

func RunHTTPServer() {
	tlsConfig, err := getTLSServerConfig()
	if err != nil {
		log.Println(err)
		return
	}

	srv := http.Server{
		Addr:      ":8000",
		TLSConfig: tlsConfig,
		Handler:   HttpHandler{},
	}
	log.Println("http server running")
	go srv.ListenAndServeTLS(serverCertFilePath, serverKeyFilePath)
	ch := make(chan struct{})
	<- ch
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		println(msg)
		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}

type HttpHandler struct{}

func (h HttpHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Println(req.TLS.PeerCertificates)
	resp.Write([]byte("hello, world"))
}
