package svid_helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
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

func TestOnX509ContextUpdate(t *testing.T) {
	svid, err := x509svid.Load(testCert, testKey)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	trustBundle, err := spiffeid.TrustDomainFromString("spiffe://example.org")
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	bundles, err := x509bundle.Load(trustBundle, testBundle)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}

	tCases := []struct {
		podID             string
		svids             *workloadapi.X509Context
		expectOutputFiles bool
	}{
		// 0. complete svids
		{
			podID: "spiffe://example.org/test/0",
			svids: &workloadapi.X509Context{
				SVIDs: []*x509svid.SVID{
					&x509svid.SVID{
						ID:           spiffeid.RequireFromString("spiffe://example.org/test/0"),
						Certificates: svid.Certificates,
						PrivateKey:   svid.PrivateKey,
					},
				},
				Bundles: x509bundle.NewSet(bundles),
			},
			expectOutputFiles: true,
		},
		// 1. expected Pod SPIFFE ID isn't included
		{
			podID: "spiffe://example.org/test/1",
			svids: &workloadapi.X509Context{
				SVIDs: []*x509svid.SVID{
					&x509svid.SVID{
						ID:           spiffeid.RequireFromString("spiffe://example.org/foo/bar"),
						Certificates: svid.Certificates,
						PrivateKey:   svid.PrivateKey,
					},
				},
				Bundles: x509bundle.NewSet(bundles),
			},
			expectOutputFiles: false,
		},
	}

	for i, tc := range tCases {
		svidPath, err := os.MkdirTemp("", "pod-svid-helper")
		if err != nil {
			t.Errorf("#%v: Unexpected error: %v", i, err)
		}
		watcher := &x509Watcher{
			logger:       testLogger(),
			mustSPIFFEID: spiffeid.RequireFromString(tc.podID),
			svidPath:     svidPath,
		}
		watcher.OnX509ContextUpdate(tc.svids)

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
	svid, err := x509svid.Load(testCert, testKey)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}

	trustBundle, err := spiffeid.TrustDomainFromString("spiffe://example.org")
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}
	bundles, err := x509bundle.Load(trustBundle, testBundle)
	if err != nil {
		t.Errorf("Unexpected erorr: failed to prepare testing: %v", err)
	}

	sh := &SVIDHelper{
		Logger: testLogger(),
	}

	tCases := []struct {
		podID                 string
		fetchX509SVIDHandler  func(context.Context, time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error)
		checkSVIDExistHandler func(path string) error
		wantErr               string
	}{
		// 0. fetchX509SVIDHandler returns complete response, and then the response is output as files
		{
			podID: "spiffe://example.org/test/0",
			fetchX509SVIDHandler: func(context.Context, time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error) {
				return &x509svid.SVID{
						ID:           spiffeid.RequireFromString("spiffe://example.org/test/0"),
						Certificates: svid.Certificates,
						PrivateKey:   svid.PrivateKey,
					},
					bundles,
					nil
			},
			checkSVIDExistHandler: checkSVIDFileExist,
		},
		// 1. fetchX509SVIDHandler returns error
		{
			podID: "spiffe://example.org/test/1",
			fetchX509SVIDHandler: func(context.Context, time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error) {
				return nil, nil, errors.New("fake handler error")
			},
			checkSVIDExistHandler: checkSVIDFileExist,
			wantErr:               "unable to fetch SVID: fake handler error",
		},
		// 2. SVID already exists
		{
			podID: "spiffe://example.org/test/2",
			fetchX509SVIDHandler: func(context.Context, time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error) {
				return &x509svid.SVID{
						ID:           spiffeid.RequireFromString("spiffe://example.org/test/2"),
						Certificates: svid.Certificates,
						PrivateKey:   svid.PrivateKey,
					},
					bundles,
					nil
			},
			checkSVIDExistHandler: func(string) error {
				return errors.New("fake exist error")
			},
			wantErr: "fake exist error",
		},
	}

	for i, tc := range tCases {
		svidPath, err := os.MkdirTemp("", "pod-svid-helper")
		if err != nil {
			t.Errorf("#%v: Unexpected error: %v", i, err)
		}
		sh.SVIDPath = svidPath
		sh.PodSPFFEID, err = spiffeid.FromString(tc.podID)
		if err != nil {
			t.Errorf("#%v: Unexpected error: %v", i, err)
		}
		sh.fetchX509SVIDHandler = tc.fetchX509SVIDHandler
		sh.checkSVIDExistHandler = tc.checkSVIDExistHandler

		err = sh.RunModeInit()
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
	svidPath, err := os.MkdirTemp("", "pod-svid-helper")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	svidFileName := filepath.Join(svidPath, "svid.pem")
	if err := os.WriteFile(svidFileName, []byte("test-data"), 0644); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if err := checkSVIDFileExist(svidPath); err == nil {
		t.Error("expect error, got nil")
	}
}
