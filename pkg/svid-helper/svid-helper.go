package svid_helper

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"go.uber.org/zap"
)

var (
	svidFilePattern = "svid*.pem"
	defaultTimeOut  = 5 * time.Second
)

// Mode represents the behavior of the helper
// 'init': helper fetches SVIDs and outputs them.
// 'refresh: helper outputs new SVIDs if SVIDs are rotated
type Mode int

const (
	Unknown Mode = iota
	Init
	Refresh
)

// NewMode converts given mode string to Mode
func NewMode(mode string) Mode {
	mode = strings.ToUpper(mode)
	switch mode {
	case "INIT":
		return Init
	case "REFRESH":
		return Refresh
	default:
		return Unknown
	}
}

// Artifact represents the artifact which fetched via Workload API
type Artifact struct {
	// PEM Formatted Certificate data
	SVID []byte
	// PEM Formatted Private Key
	PrivateKey []byte
	// PEM Formatted Certificate data
	Bundle []byte
}

// SVIDHelper represents the configuration of helper
// SVIDHelper also implements workload.SVIDWatcher
type SVIDHelper struct {
	Logger          *zap.SugaredLogger
	WorkloadAPIPath string
	SVIDPath        string
	PodSPFFEID      spiffeid.ID

	fetchX509SVIDHandler  func(context.Context, time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error)
	checkSVIDExistHandler func(path string) error
}

// New returns new *SVIDHelper with given values.
func New(logger *zap.SugaredLogger, wlAPIPath, svidPath string, podSPIFFEID spiffeid.ID) *SVIDHelper {
	h := &SVIDHelper{
		Logger:                logger,
		WorkloadAPIPath:       wlAPIPath,
		SVIDPath:              svidPath,
		PodSPFFEID:            podSPIFFEID,
		checkSVIDExistHandler: checkSVIDFileExist,
	}
	h.fetchX509SVIDHandler = h.fetchX509SVID
	return h
}

// runModeInit fetch X509SVIDs and output them to given path(sh.SVIDPath)
func (sh *SVIDHelper) RunModeInit() error {
	if err := sh.checkSVIDExistHandler(sh.SVIDPath); err != nil {
		return err
	}

	ctx := context.Background()
	svid, bundle, err := sh.fetchX509SVIDHandler(ctx, defaultTimeOut)
	if err != nil {
		return fmt.Errorf("unable to fetch SVID: %v", err)
	}

	pemSVID := pemutil.EncodeCertificates(svid.Certificates)
	pemKey, err := pemutil.EncodePKCS8PrivateKey(svid.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse Private Key for (%v): %v", svid.ID.String(), err)
	}

	pemBundle := pemutil.EncodeCertificates(bundle.X509Authorities())
	if err != nil {
		return fmt.Errorf("failed to parse Bundle for (%v): %v", svid.ID.TrustDomain(), err)
	}

	artifact := &Artifact{
		SVID:       pemSVID,
		PrivateKey: pemKey,
		Bundle:     pemBundle,
	}

	if err := writeResponse(artifact, sh.SVIDPath); err != nil {
		return fmt.Errorf("failed to ouput response: %v", err)
	}

	sh.Logger.Info("Init SVID is successfully")
	return nil
}

// runModeRefresh rotates SVIDs if they are renewed
func (sh *SVIDHelper) RunModeRefresh() {
	ctx := context.Background()
	sh.watchX509SVID(ctx)
}

func (sh *SVIDHelper) svidPicker(svids []*x509svid.SVID) *x509svid.SVID {
	for _, svid := range svids {
		if svid.ID == sh.PodSPFFEID {
			sh.Logger.Debugf("SVID fetched for SPIFFE ID: %q", svid.ID.String())
			return svid
		}
	}
	return nil
}

// fetchX509SVID fetches X509SVID from Workload API.
func (sh *SVIDHelper) fetchX509SVID(ctx context.Context, timeout time.Duration) (*x509svid.SVID, *x509bundle.Bundle, error) {
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithLogger(sh.Logger), workloadapi.WithAddr(sh.WorkloadAPIPath)),
		workloadapi.WithDefaultX509SVIDPicker(sh.svidPicker))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to prepare workload api client: %v", err)
	}
	defer source.Close()

	bundle, err := source.GetX509BundleForTrustDomain(sh.PodSPFFEID.TrustDomain())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch x509 bundle: %v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch x509 svid: %v", err)
	}

	return svid, bundle, nil
}

func (sh *SVIDHelper) watchX509SVID(ctx context.Context) {
	var wg sync.WaitGroup

	client, err := workloadapi.New(ctx,
		workloadapi.WithLogger(sh.Logger),
		workloadapi.WithAddr(sh.WorkloadAPIPath),
	)
	if err != nil {
		sh.Logger.Errorf("Failed to prepare workload client: %v", err)
	}
	defer client.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := client.WatchX509Context(ctx, &x509Watcher{
			logger:       sh.Logger,
			mustSPIFFEID: sh.PodSPFFEID,
			svidPath:     sh.SVIDPath,
		})
		if err != nil && status.Code(err) != codes.Canceled {
			sh.Logger.Errorf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Wait()
}

type x509Watcher struct {
	logger       *zap.SugaredLogger
	mustSPIFFEID spiffeid.ID
	svidPath     string
}

// UpdateX509SVIDs is run every time an SVID is updated
func (w *x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		if svid.ID != w.mustSPIFFEID {
			continue
		}

		pemSVID := pemutil.EncodeCertificates(svid.Certificates)
		pemPrivateKey, err := pemutil.EncodePKCS8PrivateKey(svid.PrivateKey)
		if err != nil {
			w.logger.Errorf("Failed to encode private-key %v: %v", svid.ID.String(), err)
			continue
		}
		bundles, err := c.Bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
		if err != nil {
			w.logger.Errorf("Failed to get trust-bundle for %v: %v", svid.ID.TrustDomain(), err)
			continue
		}
		pemBundles := pemutil.EncodeCertificates(bundles.X509Authorities())

		artifact := &Artifact{
			SVID:       pemSVID,
			PrivateKey: pemPrivateKey,
			Bundle:     pemBundles,
		}

		if err := writeResponse(artifact, w.svidPath); err != nil {
			w.logger.Errorf("Failed to rotate the new SVID for %v: %v", svid.ID.String(), err)
			continue
		}

		w.logger.Infof("SVID updated for spiffeID: %q", svid.ID.String())
		return
	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (w *x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		w.logger.Errorf("Watch X.509 SVID error: %v", err)
	}
}

func checkSVIDFileExist(path string) error {
	searchSVIDsExist := filepath.Join(path, svidFilePattern)
	f, err := filepath.Glob(searchSVIDsExist)
	if err != nil {
		return err
	}
	if len(f) != 0 {
		return fmt.Errorf("SVIDs already exist in the given svid-path")
	}
	return nil
}

// writeResponse outputs 'artifact' to 'opPath'
func writeResponse(artifact *Artifact, opPath string) error {
	// Write SVID
	sfp := filepath.Join(opPath, "svid.pem")
	if err := ioutil.WriteFile(sfp, artifact.SVID, 0644); err != nil {
		return fmt.Errorf("failed to write SVID to %v: %v", sfp, err)
	}

	// Write Private Key
	kfp := filepath.Join(opPath, "svid-key.pem")
	if err := ioutil.WriteFile(kfp, artifact.PrivateKey, 0400); err != nil {
		return fmt.Errorf("failed to write SVID to %v: %v", kfp, err)
	}

	// Write Bundle
	bfp := filepath.Join(opPath, "bundle.pem")
	if err := ioutil.WriteFile(bfp, artifact.Bundle, 0644); err != nil {
		return fmt.Errorf("failed to write Bundle to %v: %v", bfp, err)
	}
	return nil
}
