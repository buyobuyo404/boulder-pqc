package pqc

import (
	falcon512 "crypto/pqc/falcon/falcon512"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestCreateSelfSignedCertificatePQC(t *testing.T) {
	random := rand.Reader

	pqcPriv, err := falcon512.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate pqc key: %s", err)
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	commonName := "test.example.com"
	template := x509.Certificate{
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		SignatureAlgorithm: x509.PureFalcon512,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

		PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains:     []string{".example.com", "example.com"},
		ExcludedDNSDomains:      []string{"bar.example.com"},
		PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
		ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
		PermittedEmailAddresses: []string{"foo@example.com"},
		ExcludedEmailAddresses:  []string{".example.com", "example.com"},
		PermittedURIDomains:     []string{".bar.com", "bar.com"},
		ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	derBytes, err := x509.CreateCertificate(random, &template, &template, &pqcPriv.PublicKey, pqcPriv)
	//
	if err != nil {
		t.Errorf("%s: failed to create certificate: %s", "pqc", err)
	}

	cert, err := x509.ParseCertificate(derBytes)

	fmt.Println("cert: ", cert)

	block := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}

	file, err := os.Create("test-ca-falcon512.crt")
	defer file.Close()
	pem.Encode(file, &block)
}

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCreateCertificateRequestPQC(t *testing.T) {
	random := rand.Reader

	pqcPriv, err := falcon512.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate faclon512 key: %s", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		SignatureAlgorithm: x509.PureFalcon512,
		DNSNames:           []string{"test.example.com"},
		EmailAddresses:     []string{"gopher@golang.org"},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
	}

	derBytes, err := x509.CreateCertificateRequest(random, &template, pqcPriv)

	csr, err := x509.ParseCertificateRequest(derBytes)
	fmt.Println(csr)

	block := pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   derBytes,
	}

	file, err := os.Create("falcon512.der.csr")
	defer file.Close()
	pem.Encode(file, &block)
}

//func TestSign(t *testing.T) {
//	priv, _ := falcon512.GenerateKey()
//	sign, _ := falcon512.Sign2(priv, []byte("0000"))
//
//	//fmt.Println("sk: ", priv.Sk)
//
//	falcon512.Verify(&priv.PublicKey, []byte("0000"), sign)
//
//	//fmt.Println("pk: ", priv.Pk)
//}
//
//func TestSign2(t *testing.T) {
//	priv, _ := falcon512.GenerateKey()
//	priv.SignTest([]byte("0000"))
//
//	//fmt.Println("sk: ", priv.Sk)
//
//	//falcon512.Verify(&priv.PublicKey, []byte("0000"), sign)
//
//	//fmt.Println("pk: ", priv.Pk)
//}

//func TestPQCSignSK(t *testing.T) {
//	priv, _ := falcon512.GenerateKey()
//	//priv.Sign([]byte("0000"))
//
//	priv.SignPQC2([]byte("0000"))
//
//	fmt.Println(priv.Sk)
//
//	priv.SignPQC2([]byte("1111"))
//
//	fmt.Println(priv.Sk)
//
//	priv2, _ := falcon512.GenerateKey()
//	//priv.Sign([]byte("0000"))
//
//	priv2.SignPQC2([]byte("0000"))
//
//	fmt.Println(priv.Sk)
//
//	//fmt.Println("sk: ", priv.Sk)
//
//	//falcon512.Verify(&priv.PublicKey, []byte("0000"), sign)
//
//	//fmt.Println("pk: ", priv.Pk)
//}
