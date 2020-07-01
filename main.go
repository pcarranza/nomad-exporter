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

	apiClient, err := api.NewClient(configureWith(a))
	if err != nil {
		logrus.Fatalf("could not create api client: %s", err)
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
	prometheus.MustRegister(exporter)

	http.HandleFunc("/", rootFunc(a.MetricsPath))
	http.HandleFunc("/status", statusFunc(exporter))
	http.Handle(a.MetricsPath, prometheus.Handler())

	logrus.Println("Listening on", a.ListenAddress)
	logrus.Fatal(http.ListenAndServe(a.ListenAddress, nil))
}

func rootFunc(metricsPath string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Nomad Exporter</title></head>
             <body>
             <h1>Nomad Exporter</h1>
             <p><a href='` + metricsPath + `'>Metrics</a></p>
             </body>
			 </html>`))
	}
}

func statusFunc(e *Exporter) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		err := e.Probe()
		status := "UP"
		if err != nil {
			status = "DOWN"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Write([]byte(`<html>
		<head><title>Nomad Exporter Status</title></head>
		<body>
		<h1>Nomad Exporter Status</h1>
		<p><strong>` + status + `</strong></p>
		</body>
		</html>`))
	}
}

func configureWith(a args) *api.Config {
	timeout := time.Duration(a.NomadTimeout) * time.Millisecond
	waitTime := time.Duration(a.NomadWaitTime) * time.Millisecond

	cfg := api.DefaultConfig()
	cfg.Address = a.NomadAddress

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
		cfg.TLSConfig.CACert = a.TLSCaFile
		cfg.TLSConfig.CAPath = a.TLSCaPath
		cfg.TLSConfig.ClientKey = a.TLSKey
		cfg.TLSConfig.ClientCert = a.TLSCert
		cfg.TLSConfig.Insecure = a.TLSInsecure
		cfg.TLSConfig.TLSServerName = a.TLSServerName

		if err := api.ConfigureTLS(httpClient, cfg.TLSConfig); err != nil {
			logrus.Fatalf("failed to configure TLS: %s", err)
		}
	}

	return cfg
}
