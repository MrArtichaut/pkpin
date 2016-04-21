package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"encoding/base64"
	"crypto/sha256"
)

var flagHost = flag.String("host", "", "Extract HPKP pins from the host's certificates chain")
var flagCert = flag.String("cert", "", "Extract HPKP pin from a certificate at the given path")
var flagPKey = flag.String("pkey", "", "Extract HPKP pin from a DER encoded public key file")

func main() {

	flag.Parse()

	if *flagCert != "" {
		pinFromCertPath(*flagCert)
	} else if *flagHost != "" {
		pinsFromHost(*flagHost)
	} else if *flagPKey != "" {
		pinFromPublicKeyPath(*flagPKey)
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}

}

func pinFromCertPath(path string) {
	f, err := os.Open(path)
	check(err, "Error while opening cert at path", path)

	certData, err := ioutil.ReadAll(f)
	check(err, "Error reading cert")

	cert, err := x509.ParseCertificate(certData)
	check(err, "Error while parsing cert")

	pin := pinFromCertificate(cert)
	fmt.Printf("pin-sha256=\"%s\"\n", pin)
}

func pinsFromHost(host string) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.Dial("tcp", host, nil)
	check(err, "Error while connecting to ", host)
	defer conn.Close()

	err = conn.Handshake()
	check(err, "Error while performing TLS handshake")

	state := conn.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		log.Fatalln("No valid certificate returned by the server")
	}

	chain := state.VerifiedChains[0]
	for idx, cert := range chain {
		pin := pinFromCertificate(cert)
		fmt.Printf("%d) %s\n\tpin-sha256=\"%s\"\n\n", idx, cert.Subject.CommonName, pin)
	}
}

func pinFromPublicKeyPath(path string) {
	f, err := os.Open(path)
	check(err, "Error while opening public key at path", path)

	pkeyData, err := ioutil.ReadAll(f)
	check(err, "Error reading public key")

	pin := pinFromPublicDERPKey(pkeyData)
	fmt.Printf("pin-sha256=\"%s\"\n", pin)
}

func pinFromCertificate(cert *x509.Certificate) string {
	b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	check(err, "Error while marshaling public key")

	return pinFromPublicDERPKey(b)
}

func pinFromPublicDERPKey(b []byte) string {
	digest := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func check(err error, v ...interface{}) {
	if err != nil {
		if v != nil {
			log.Fatalln(v...)
		}
		log.Fatalln(err)
	}
}
