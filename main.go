package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var flagHost = flag.String("host", "", "Extract HPKP pin from the host's certificate")
var flagCert = flag.String("cert", "", "Extract HPKP pin from a certificate at the given path")

func main() {

	flag.Parse()

	var cert *x509.Certificate
	if *flagCert != "" {
		cert = certFromPath(*flagCert)
	} else if *flagHost != "" {
		cert = certFromHost(*flagHost)
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}

	b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	check(err, "Error while marshaling public key")

	s := base64.StdEncoding.EncodeToString(b)

	digest := sha256.Sum256(b)
	s = base64.StdEncoding.EncodeToString(digest[:])
	fmt.Printf("pin-sha256=\"%s\"\n", s)
}

func certFromPath(path string) *x509.Certificate {
	f, err := os.Open(path)
	check(err, "Error while opening cert at path", path)

	certData, err := ioutil.ReadAll(f)
	check(err, "Error reading cert")

	cert, err := x509.ParseCertificate(certData)
	check(err, "Error while parsing cert")

	return cert
}

func certFromHost(host string) *x509.Certificate {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.Dial("tcp", host, nil)
	check(err, "Error while connecting to ", host)
	defer conn.Close()

	err = conn.Handshake()
	check(err, "Error while performing TLS handshake")

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Fatalln("No certificate returned by the server")
	}

	cert := state.PeerCertificates[0]

	return cert
}

func check(err error, v ...interface{}) {
	if err != nil {
		if v != nil {
			log.Fatalln(v...)
		}
		log.Fatalln(err)
	}
}
