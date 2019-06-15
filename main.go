package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/nomad/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	cleanhttp "github.com/hashicorp/go-cleanhttp"

	"gitlab.com/yakshaving.art/nomad-exporter/version"
)

func main() {
	a := parseArgs()

	if a.ShowVersion {
		fmt.Println(version.GetVersion())
		os.Exit(0)
	}

	if a.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	timeout := time.Duration(a.NomadTimeout) * time.Millisecond
	waitTime := time.Duration(a.NomadWaitTime) * time.Millisecond

	cfg := api.DefaultConfig()
	cfg.Address = a.NomadServer

	httpClient := cleanhttp.DefaultClient()
	transport := httpClient.Transport.(*http.Transport)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	httpClient.Timeout = timeout

	cfg.HttpClient = httpClient
	cfg.WaitTime = waitTime

	if strings.HasPrefix(cfg.Address, "https://") {
		cfg.TLSConfig.CACert = a.TlsCaFile
		cfg.TLSConfig.CAPath = a.TlsCaPath
		cfg.TLSConfig.ClientKey = a.TlsKey
		cfg.TLSConfig.ClientCert = a.TlsCert
		cfg.TLSConfig.Insecure = a.TlsInsecure
		cfg.TLSConfig.TLSServerName = a.TlsServerName
	}

	apiClient, err := api.NewClient(cfg)
	if err != nil {
		logrus.Fatalf("could not create exporter: %s", err)
	}

	exporter := &Exporter{
		client:                        apiClient,
		AllowStaleReads:               a.AllowStaleReads,
		PeerMetricsEnabled:            !a.NoPeerMetricsEnabled,
		SerfMetricsEnabled:            !a.NoSerfMetricsEnabled,
		NodeMetricsEnabled:            !a.NoNodeMetricsEnabled,
		JobMetricEnabled:              !a.NoJobMetricsEnabled,
		AllocationsMetricsEnabled:     !a.NoAllocationsMetricsEnabled,
		EvalMetricsEnabled:            !a.NoEvalMetricsEnabled,
		DeploymentMetricsEnabled:      !a.NoDeploymentMetricsEnabled,
		AllocationStatsMetricsEnabled: !a.NoAllocationStatsMetricsEnabled,
		Concurrency:                   a.Concurrency,
	}

	logrus.Debugf("Created exporter %#v", *exporter)

	prometheus.MustRegister(exporter)

	http.Handle(a.MetricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Nomad Exporter</title></head>
             <body>
             <h1>Nomad Exporter</h1>
             <p><a href='` + a.MetricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	logrus.Println("Listening on", a.ListenAddress)
	logrus.Fatal(http.ListenAndServe(a.ListenAddress, nil))
}
