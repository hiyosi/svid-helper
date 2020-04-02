package x509

import (
	"io/ioutil"
	"testing"
)

const (
	testCert = "../../../testdata/test-cert.der"
	testKey  = "../../../testdata/test-key.der"
)

func TestConvertCertificateDerToPem(t *testing.T) {
	derCert, err := ioutil.ReadFile(testCert)
	if err != nil {
		t.Errorf("Unable to load certificate file: %v", err)
	}

	tCases := []struct {
		data    []byte
		wantErr bool
	}{
		// 0. Convert successfully
		{
			data:    derCert,
			wantErr: false,
		},
		// 1. Invalid DER data
		{
			data:    []byte("invalid-data"),
			wantErr: true,
		},
	}

	for i, tc := range tCases {
		_, err = ConvertCertificateDERToPEM(tc.data)
		if !tc.wantErr && err != nil {
			t.Errorf("#%v: Unexpected Error: %v", i, err)
		}
		if tc.wantErr && err == nil {
			t.Errorf("#%v: Expect got some error, got nil", i)
		}
	}
}

func TestConvertPrivateKeyDerToPem(t *testing.T) {
	derKey, err := ioutil.ReadFile(testKey)
	if err != nil {
		t.Errorf("Unable to load private key file: %v", err)
	}

	tCases := []struct {
		data    []byte
		wantErr bool
	}{
		// 0. Convert successfully
		{
			data:    derKey,
			wantErr: false,
		},
		// 1. Invalid DER data
		{
			data:    []byte("invalid-data"),
			wantErr: true,
		},
	}

	for i, tc := range tCases {
		_, err = ConvertPrivateKeyDERToPEM(tc.data)
		if !tc.wantErr && err != nil {
			t.Errorf("#%v: Unexpected Error: %v", i, err)
		} else if tc.wantErr && err == nil {
			t.Errorf("#%v: Expect got some error, got nil", i)
		}
	}
}
