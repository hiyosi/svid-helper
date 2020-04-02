package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	svid_helper "github.com/hiyosi/pod-svid-helper/pkg/svid-helper"
	flag_util "github.com/hiyosi/pod-svid-helper/pkg/util/flag"
)

var (
	fs = pflag.NewFlagSet("", pflag.ExitOnError)

	logLevel    = fs.String("log-level", "debug", "Set the minimum level for logging")
	mode        = fs.String("mode", "init", "Behavior of the helper, 'init' or 'refresh'")
	svidPath    = fs.String("svid-path", "/tmp", "Path to the directory where output the SVIDs")
	wlAPISocket = fs.String("workload-api-socket", "/var/run/spire/agent.sock", "Path to the Workload API served by SPIRE Agent")
	podSPIFFEID = fs.String("pod-spiffe-id", "", "The SPIFFE ID which is allocated to the Pod. SVID output to svid-path is associated with the specified SPIFFE ID")
)

// newLogger returns *zap.Logger which configured with given log-level.
// logs are output to stderr.
func newSugaredLogger(logLevel string) (*zap.SugaredLogger, error) {
	zc := zap.NewProductionConfig()
	if err := zc.Level.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("failed to parse log-level: %v", err)
	}

	logger, err := zc.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize the logger: %v", err)
	}

	return logger.Sugar(), nil
}

func main() {
	flag_util.ParseEnv("HELPER", fs)
	fs.AddGoFlagSet(flag.CommandLine)
	fs.Parse(os.Args)

	logger, err := newSugaredLogger(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
	defer logger.Sync()

	helper := svid_helper.New(logger, *mode, *wlAPISocket, *svidPath, *podSPIFFEID)

	if err := helper.Run(); err != nil {
		logger.Error(err)
	}
}
