package transport

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	clientCertFilePath = "/Users/lethe/code/go/cert-http/cert/client.cer"
	clientKeyFilePath  = "/Users/lethe/code/go/cert-http/cert/client.key"
)

func RunTLSClient() {
	tlsConfig, err := getTLSClientConfig()
	if err != nil {
		log.Println(err)
		return
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:443", tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()
	n, err := conn.Write([]byte("hello\n"))
	if err != nil {
		log.Println(n, err)
		return
	}
	buf := make([]byte, 100)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}
	println(string(buf[:n]))
}

func RunHTTPClient() {
	tlsConfig, err := getTLSClientConfig()
	if err != nil {
		log.Println(err)
		return
	}
	cli := http.Client{}
	cli.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:8000", nil)
	if err != nil {
		log.Println(err)
		return 
	}
	req.TLS
	resp, err := cli.Do(req)
	if err != nil {
		log.Printf("request: %s", err)
		return
	}
	defer resp.Body.Close()
	respData, _ := ioutil.ReadAll(resp.Body)
	log.Printf("response: %s", respData)
}

func getTLSClientConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(clientCertFilePath, clientKeyFilePath)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	// certBytes, err := ioutil.ReadFile(clientCertFilePath)
	// if err != nil {
	// 	panic("Unable to read cert.pem")
	// }
	// clientCertPool := x509.NewCertPool()
	// ok := clientCertPool.AppendCertsFromPEM(certBytes)
	// if !ok {
	// 	panic("failed to parse root certificate")
	// }

	conf := &tls.Config{
		// RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	return conf, nil
}
