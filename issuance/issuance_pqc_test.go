package issuance

import (
	"crypto/pqc/falcon/falcon512"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/test"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

func defaultProfileConfigPQC() ProfileConfig {
	profileConfig := ProfileConfig{
		AllowCommonName: true,
		AllowCTPoison:   true,
		AllowSCTList:    true,
		AllowMustStaple: true,
		Policies: []PolicyInformation{
			{OID: "1.2.3"},
		},
		MaxValidityPeriod:   cmd.ConfigDuration{Duration: time.Hour},
		MaxValidityBackdate: cmd.ConfigDuration{Duration: time.Hour},
	}

	//fmt.Println("profileConfig: ", profileConfig)

	return profileConfig
}

func defaultIssuerConfigPQC() IssuerConfig {
	issuerConfig := IssuerConfig{
		UseForECDSALeaves: true,
		UseForRSALeaves:   true,

		UseForFalcon512Leaves:  true,
		UseForFalcon1024Leaves: true,

		UseForDilithium2Leaves:    true,
		UseForDilithium3Leaves:    true,
		UseForDilithium5Leaves:    true,
		UseForDilithium2AESLeaves: true,
		UseForDilithium3AESLeaves: true,
		UseForDilithium5AESLeaves: true,

		UseForRainbowIIIClassicLeaves:        true,
		UseForRainbowIIICircumzenithalLeaves: true,
		UseForRainbowIIICompressedLeaves:     true,
		UseForRainbowVClassicLeaves:          true,
		UseForRainbowVCircumzenithalLeaves:   true,
		UseForRainbowVCompressedLeaves:       true,

		IssuerURL: "http://issuer-url",
		OCSPURL:   "http://ocsp-url",
	}
	//fmt.Println("issuerConfig: ", issuerConfig)

	return issuerConfig
}

func defaultProfilePQC() *Profile {
	p, _ := NewProfile(defaultProfileConfigPQC(), defaultIssuerConfigPQC())
	return p
}

var issuerCertPQC *Certificate

var issuerSignerPQC *falcon512.PrivateKey

func func2() *Certificate {
	tk, err := falcon512.GenerateKey()
	cmd.FailOnError(err, "failed to generate falcon512 test key")
	issuerSignerPQC = tk
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "big ca pqc",
		},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	issuer, err := x509.CreateCertificate(rand.Reader, template, template, tk.Public(), tk)
	cmd.FailOnError(err, "failed to generate test issuer")
	cert, err := x509.ParseCertificate(issuer)
	cmd.FailOnError(err, "failed to parse test issuer")
	issuerCertPQC = &Certificate{Certificate: cert}
	return issuerCertPQC
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

func TestMain(m *testing.M) {
	func2()
	//CreateSelfSignedCertificatePQC()
	os.Exit(m.Run())
}

func Test(t *testing.T) {
	testsk, _ := falcon512.GenerateKey()
	fmt.Println("testsk.Public(): ", testsk.Public())

	switch k := testsk.Public().(type) {
	case *falcon512.PublicKey:
		fmt.Println("k: ", k)
	}

}
func TestIssuePQC(t *testing.T) {
	fc := clock.NewFake()
	//issuerSignerPQC, _ := falcon512.GenerateKey()
	fc.Set(time.Now())
	linter, err := linter.New(
		issuerCertPQC.Certificate,
		issuerSignerPQC,
		[]string{"w_ct_sct_policy_count_unsatisfied"},
	)
	test.AssertNotError(t, err, "failed to create linter")
	signer, err := NewIssuer(issuerCertPQC, issuerSignerPQC, defaultProfilePQC(), linter, fc)

	fmt.Println(signer.Algs())

	test.AssertNotError(t, err, "NewIssuer failed")
	pk, err := falcon512.GenerateKey()
	test.AssertNotError(t, err, "failed to generate test key")

	issuanceRequest := &IssuanceRequest{
		PublicKey: pk.Public(),
		Serial:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
		DNSNames:  []string{"example.com"},
		NotBefore: fc.Now(),
		NotAfter:  fc.Now().Add(time.Hour - time.Second),
	}

	certBytes, err := signer.Issue(issuanceRequest)

	test.AssertNotError(t, err, "Issue failed")
	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "failed to parse certificate")

	err = cert.CheckSignatureFrom(issuerCertPQC.Certificate)
	if err != nil {
		fmt.Println("yes, there is an error")
	}

	test.AssertNotError(t, err, "signature validation failed")
	test.AssertByteEquals(t, cert.SerialNumber.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
	test.AssertDeepEquals(t, cert.PublicKey, pk.Public())
	test.AssertEquals(t, len(cert.Extensions), 8) // Constraints, KU, EKU, SKID, AKID, AIA, SAN, Policies
	test.AssertEquals(t, cert.KeyUsage, x509.KeyUsageDigitalSignature)
}
