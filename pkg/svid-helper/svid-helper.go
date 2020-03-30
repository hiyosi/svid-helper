package svid_helper

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	workload_proto "github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/workload"
	workload_dial "github.com/spiffe/spire/api/workload/dial"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"go.uber.org/zap"

	workload_util "github.com/hiyosi/pod-svid-helper/pkg/util/spire/api/workload"
	x509_util "github.com/hiyosi/pod-svid-helper/pkg/util/x509"
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
	Mode            string
	WorkloadAPIPath string
	SVIDPath        string
	PodSPFFEID      string

	fetchX509SVIDHandler  func(context.Context, time.Duration, string) (*workload_proto.X509SVIDResponse, error)
	checkSVIDExistHandler func(path string) error
}

// New returns new *SVIDHelper with given values.
func New(logger *zap.SugaredLogger, mode string, wlAPIPath, svidPath, podSPIFFEID string) *SVIDHelper {
	return &SVIDHelper{
		Logger:                logger,
		Mode:                  mode,
		WorkloadAPIPath:       wlAPIPath,
		SVIDPath:              svidPath,
		PodSPFFEID:            podSPIFFEID,
		fetchX509SVIDHandler:  fetchX509SVID,
		checkSVIDExistHandler: checkSVIDFileExist,
	}
}

// UpdateX509SVIDs is run every time an SVID is updated
func (sh *SVIDHelper) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	for _, svid := range svids.SVIDs {
		if svid.SPIFFEID != sh.PodSPFFEID {
			continue
		}

		pemSVID := pemutil.EncodeCertificates(svid.Certificates)
		pemPrivateKey, err := pemutil.EncodePKCS8PrivateKey(svid.PrivateKey)
		if err != nil {
			sh.Logger.Error("Failed to prepare the new SVID for %v: %v", svid.SPIFFEID, err)
			continue
		}
		pemBundle := pemutil.EncodeCertificates(svid.TrustBundle)

		artifact := &Artifact{
			SVID:       pemSVID,
			PrivateKey: pemPrivateKey,
			Bundle:     pemBundle,
		}

		if err := writeResponse(artifact, sh.SVIDPath); err != nil {
			sh.Logger.Error("Failed to rotate the SVID for %v: %v", svid.SPIFFEID, err)
			continue
		}

		sh.Logger.Infof("SVID updated for spiffeID: %q", svid.SPIFFEID)
		return
	}
}

// OnError is run when the client runs into an error
func (sh *SVIDHelper) OnError(err error) {
	sh.Logger.Infof("X509SVIDClient error: %v", err)
}

// runModeInit fetch X509SVIDs and output them to given path(sh.SVIDPath)
func (sh *SVIDHelper) runModeInit() error {
	ctx := context.Background()
	resp, err := sh.fetchX509SVIDHandler(ctx, defaultTimeOut, sh.WorkloadAPIPath)
	if err != nil {
		return fmt.Errorf("unable to fetch SVID: %v", err)
	}

	if err := sh.checkSVIDExistHandler(sh.SVIDPath); err != nil {
		return err
	}

	for _, svid := range resp.Svids {
		spiffeID := svid.GetSpiffeId()
		sh.Logger.Debugf("spiffeID=%v, pod-spiffe-id=%v", spiffeID, sh.PodSPFFEID)
		if spiffeID != sh.PodSPFFEID {
			continue
		}

		sh.Logger.Infof("SVID fetched for SPIFFE ID: %q", spiffeID)

		pemSVID, err := x509_util.ConvertCertificateDERToPEM(svid.GetX509Svid())
		if err != nil {
			return fmt.Errorf("failed to parse SVID for (%v): %v", spiffeID, err)
		}
		pemKey, err := x509_util.ConvertPrivateKeyDERToPEM(svid.GetX509SvidKey())
		if err != nil {
			return fmt.Errorf("failed to parse Private Key for (%v): %v", spiffeID, err)
		}
		pemBundle, err := x509_util.ConvertCertificateDERToPEM(svid.GetBundle())
		if err != nil {
			return fmt.Errorf("failed to parse Bundle for (%v): %v", spiffeID, err)
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
	}
	return nil
}

// runModeRefresh rotates SVIDs if they are renewed
func (sh *SVIDHelper) runModeRefresh() error {
	x509SVIDClient, err := workload.NewX509SVIDClient(sh, workload.WithAddr(fmt.Sprintf("unix://%v", sh.WorkloadAPIPath)))
	if err != nil {
		return fmt.Errorf("unable to create x509SVIDClient: %v", err)
	}

	if err := x509SVIDClient.Start(); err != nil {
		return fmt.Errorf("unable to start x509SVIDClient: %v", err)
	}

	waitShutdown()

	if err := x509SVIDClient.Stop(); err != nil {
		return fmt.Errorf("unable to properly stop x509SVIDClient: %v", err)
	}

	return nil
}

// Run runs SVIDHelper as given mode(sh.Mode)
func (sh *SVIDHelper) Run() error {
	mode := NewMode(sh.Mode)
	switch mode {
	case Init:
		sh.Logger.Debug("Run init mode")
		return sh.runModeInit()
	case Refresh:
		sh.Logger.Debug("Run refresh mode")
		return sh.runModeRefresh()
	default:
		return fmt.Errorf("unkown mode: %v", sh.Mode)
	}
}

// waitShutdown waits until an os.Interrupt signal is sent (ctrl + c)
func waitShutdown() {
	var wg sync.WaitGroup
	wg.Add(1)

	var signalCh chan os.Signal
	signalCh = make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		wg.Done()
	}()

	wg.Wait()
}

// fetchX509SVID fetches X509SVID from Workload API.
func fetchX509SVID(ctx context.Context, timeout time.Duration, apiPath string) (*workload_proto.X509SVIDResponse, error) {
	conn, err := workload_dial.Dial(ctx, &net.UnixAddr{
		Name: apiPath,
		Net:  "unix",
	})
	if err != nil {
		return nil, fmt.Errorf("unable to connect to API via %v: %v", apiPath, err)
	}
	client := workload_proto.NewSpiffeWorkloadAPIClient(conn)

	ctx, cancel := workload_util.PrepareAPIContext(ctx, timeout)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload_proto.X509SVIDRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("unable to receive SVID from stream: %v", err)
	}

	return resp, nil
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
