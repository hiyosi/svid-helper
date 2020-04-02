package svid_helper

import (
	"context"
	"crypto"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	workload_proto "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/workload"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"go.uber.org/zap"
)

const (
	testBundle    = "../../testdata/rootCA.pem"
	testBundleDER = "../../testdata/rootCA.der"
	testCert      = "../../testdata/test-cert.pem"
	testCertDER   = "../../testdata/test-cert.der"
	testKey       = "../../testdata/test-key.pem"
	testKeyDER    = "../../testdata/test-key.der"
)

func testLogger() *zap.SugaredLogger {
	z, _ := zap.NewDevelopment()
	return z.Sugar()
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func TestNewMode(t *testing.T) {
	tCases := []struct {
		mode     string
		wantMode Mode
	}{
		// 0. expect Unknown
		{
			mode:     "invalid",
			wantMode: Unknown,
		},
		// 1. expect Init
		{
			mode:     "init",
			wantMode: Init,
		},
		// 2. expect Refresh
		{
			mode:     "refresh",
			wantMode: Refresh,
		},
	}

	for i, tc := range tCases {
		got := NewMode(tc.mode)
		if got != tc.wantMode {
			t.Errorf("#%v: got %v, want %v", i, got, tc.wantMode)
		}
	}
}

func TestUpdateX509SVIDs(t *testing.T) {
	bundles, err := pemutil.LoadCertificates(testBundle)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	certificates, err := pemutil.LoadCertificates(testCert)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	privateKey, err := pemutil.LoadPrivateKey(testKey)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}

	sh := &SVIDHelper{
		Logger: testLogger(),
	}

	tCases := []struct {
		podID             string
		svids             *workload.X509SVIDs
		expectOutputFiles bool
	}{
		// 0. complete svids
		{
			podID: "spiffe://example.org/test/0",
			svids: &workload.X509SVIDs{
				SVIDs: []*workload.X509SVID{
					{
						SPIFFEID:     "spiffe://example.org/test/0",
						PrivateKey:   privateKey.(crypto.Signer),
						Certificates: certificates,
						TrustBundle:  bundles,
					},
				},
			},
			expectOutputFiles: true,
		},
		// 1. invalid private key data
		{
			podID: "spiffe://example.org/test/1",
			svids: &workload.X509SVIDs{
				SVIDs: []*workload.X509SVID{
					{
						SPIFFEID:     "spiffe://example.org/test/0",
						PrivateKey:   privateKey.(crypto.Signer),
						Certificates: certificates,
						TrustBundle:  bundles,
					},
				},
			},
			expectOutputFiles: false,
		},
		// 2. expected Pod SPIFFE ID isn't included
		{
			podID: "spiffe://example.org/test/1",
			svids: &workload.X509SVIDs{
				SVIDs: []*workload.X509SVID{
					{
						SPIFFEID:     "spiffe://example.org/test/foo",
						PrivateKey:   privateKey.(crypto.Signer),
						Certificates: certificates,
						TrustBundle:  bundles,
					},
				},
			},
			expectOutputFiles: false,
		},
	}

	for i, tc := range tCases {
		svidPath, err := ioutil.TempDir("", "pod-svid-helper")
		if err != nil {
			t.Errorf("#%v: Unexpected error: %v", i, err)
		}
		sh.SVIDPath = svidPath
		sh.PodSPFFEID = tc.podID

		sh.UpdateX509SVIDs(tc.svids)

		if tc.expectOutputFiles {
			if !fileExists(filepath.Join(svidPath, "svid.pem")) ||
				!fileExists(filepath.Join(svidPath, "svid-key.pem")) ||
				!fileExists(filepath.Join(svidPath, "bundle.pem")) {
				t.Errorf("#%v: expect some files are exist, but isn't", i)
			}
		} else {
			if fileExists(filepath.Join(svidPath, "svid.pem")) ||
				fileExists(filepath.Join(svidPath, "svid-key.pem")) ||
				fileExists(filepath.Join(svidPath, "bundle.pem")) {
				t.Errorf("#%v: expect some files aren't exist, but found them", i)
			}
		}
	}
}

func TestRunModeInit(t *testing.T) {
	bundles, err := ioutil.ReadFile(testBundleDER)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	certificates, err := ioutil.ReadFile(testCertDER)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	privateKey, err := ioutil.ReadFile(testKeyDER)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}

	sh := &SVIDHelper{
		Logger: testLogger(),
	}

	tCases := []struct {
		podID                 string
		fetchX509SVIDHandler  func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error)
		checkSVIDExistHandler func(path string) error
		wantErr               string
	}{
		// 0. fetchX509SVIDHandler returns complete response, and then the response is output as files
		{
			podID: "spiffe://example.org/test/0",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return &workload_proto.X509SVIDResponse{
					Svids: []*workload_proto.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/test/0",
							X509Svid:    certificates,
							X509SvidKey: privateKey,
							Bundle:      bundles,
						},
					},
				}, nil
			},
			checkSVIDExistHandler: checkSVIDFileExist,
		},
		// 1. fetchX509SVIDHandler returns error
		{
			podID: "spiffe://example.org/test/1",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return nil, errors.New("fake handler error")
			},
			wantErr: "unable to fetch SVID: fake handler error",
		},
		// 2. SVID already exists
		{
			podID: "spiffe://example.org/test/2",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return &workload_proto.X509SVIDResponse{
					Svids: []*workload_proto.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/test/2",
							X509Svid:    certificates,
							X509SvidKey: privateKey,
							Bundle:      bundles,
						},
					},
				}, nil
			},
			checkSVIDExistHandler: func(string) error {
				return errors.New("fake exist error")
			},
			wantErr: "fake exist error",
		},
		// 3. fetchX509SVIDHandler returns invalid X509svid data
		{
			podID: "spiffe://example.org/test/3",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return &workload_proto.X509SVIDResponse{
					Svids: []*workload_proto.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/test/3",
							X509Svid:    []byte("fake svid"),
							X509SvidKey: privateKey,
							Bundle:      bundles,
						},
					},
				}, nil
			},
			checkSVIDExistHandler: checkSVIDFileExist,
			wantErr:               "failed to parse SVID for (spiffe://example.org/test/3)",
		},
		// 4. fetchX509SVIDHandler returns invalid X509key data
		{
			podID: "spiffe://example.org/test/3",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return &workload_proto.X509SVIDResponse{
					Svids: []*workload_proto.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/test/3",
							X509Svid:    certificates,
							X509SvidKey: []byte("fake key"),
							Bundle:      bundles,
						},
					},
				}, nil
			},
			checkSVIDExistHandler: checkSVIDFileExist,
			wantErr:               "failed to parse Private Key for (spiffe://example.org/test/3)",
		},
		// 5. fetchX509SVIDHandler returns invalid bundle data
		{
			podID: "spiffe://example.org/test/3",
			fetchX509SVIDHandler: func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error) {
				return &workload_proto.X509SVIDResponse{
					Svids: []*workload_proto.X509SVID{
						{
							SpiffeId:    "spiffe://example.org/test/3",
							X509Svid:    certificates,
							X509SvidKey: privateKey,
							Bundle:      []byte("fake bundle"),
						},
					},
				}, nil
			},
			checkSVIDExistHandler: checkSVIDFileExist,
			wantErr:               "failed to parse Bundle for (spiffe://example.org/test/3)",
		},
	}

	for i, tc := range tCases {
		svidPath, err := ioutil.TempDir("", "pod-svid-helper")
		if err != nil {
			t.Errorf("#%v: Unexpected error: %v", i, err)
		}
		sh.SVIDPath = svidPath
		sh.PodSPFFEID = tc.podID
		sh.fetchX509SVIDHandler = tc.fetchX509SVIDHandler
		sh.checkSVIDExistHandler = tc.checkSVIDExistHandler

		err = sh.runModeInit()
		if tc.wantErr != "" {
			if !strings.HasPrefix(err.Error(), tc.wantErr) {
				t.Errorf("#%v: expect error %v, got %v", i, tc.wantErr, err.Error())
			}
		} else {
			if !fileExists(filepath.Join(svidPath, "svid.pem")) ||
				!fileExists(filepath.Join(svidPath, "svid-key.pem")) ||
				!fileExists(filepath.Join(svidPath, "bundle.pem")) {
				t.Errorf("#%v: expect some files are exist, but isn't", i)
			}
		}
	}
}

func TestCheckSVIDFileExist(t *testing.T) {
	svidPath, err := ioutil.TempDir("", "pod-svid-helper")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	svidFileName := filepath.Join(svidPath, "svid.pem")
	if err := ioutil.WriteFile(svidFileName, []byte("test-data"), 0644); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if err := checkSVIDFileExist(svidPath); err == nil {
		t.Error("expect error, got nil")
	}
}
