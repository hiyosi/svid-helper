package x509

import (
	"crypto/x509"
	"fmt"

	"github.com/spiffe/spire/pkg/common/pemutil"
)

// ConvertCertificateDERToPEM converts given DER formatted certificates to PEM formatted.
func ConvertCertificateDERToPEM(der []byte) ([]byte, error) {
	certObj, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DER: %v", err)
	}
	return pemutil.EncodeCertificates(certObj), nil
}

// ConvertPrivateKeyDERToPEM converts given DER formatted certificates to PEM formatted.
func ConvertPrivateKeyDERToPEM(der []byte) ([]byte, error) {
	keyObj, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Private Key: %v", err)
	}
	key, err := pemutil.EncodePKCS8PrivateKey(keyObj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Private Key: %v", err)
	}
	return key, nil
}
