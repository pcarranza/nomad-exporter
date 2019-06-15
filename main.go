package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/nomad/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"gitlab.com/yakshaving.art/nomad-exporter/version"
)

func main() {
	var (
		showVersion = flag.Bool(
			"version", false, "Print version information.")
		listenAddress = flag.String(
			"web.listen-address", ":9441", "Address to listen on for web interface and telemetry.")
		metricsPath = flag.String(
			"web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		nomadServer = flag.String(
			"nomad.server", "http://localhost:4646", "HTTP API address of a Nomad server or agent.")
		nomadTimeout = flag.Int(
			"nomad.timeout", 500, "HTTP read timeout when talking to the Nomad agent. In milliseconds")
		nomadWaitTime = flag.Int(
			"nomad.waittime", 10, "Timeout to wait for the Nomad agent to deliver fresh data. In milliseconds.")
		tlsCaFile = flag.String(
			"tls.ca-file", "", "ca-file path to a PEM-encoded CA cert file to use to verify the connection to nomad server")
		tlsCaPath = flag.String(
			"tls.ca-path", "", "ca-path is the path to a directory of PEM-encoded CA cert files to verify the connection to nomad server")
		tlsCert = flag.String(
			"tls.cert-file", "", "cert-file is the path to the client certificate for Nomad communication")
		tlsKey = flag.String(
			"tls.key-file", "", "key-file is the path to the key for cert-file")
		tlsInsecure = flag.Bool(
			"tls.insecure", false, "insecure enables or disables SSL verification")
		tlsServerName = flag.String(
			"tls.tls-server-name", "", "tls-server-name sets the SNI for Nomad ssl connection")
		debug = flag.Bool(
			"debug", false, "enable debug log level",
		)
		allowStaleReads = flag.Bool(
			"allow-stale-reads", false, "allow to read metrics from a non-leader server",
		)
		noPeerMetricsEnabled            = flag.Bool("no-peer-metrics", false, "disable peer metrics collection")
		noSerfMetricsEnabled            = flag.Bool("no-serf-metrics", false, "disable serf metrics collection")
		noNodeMetricsEnabled            = flag.Bool("no-node-metrics", false, "disable node metrics collection")
		noJobMetricsEnabled             = flag.Bool("no-jobs-metrics", false, "disable jobs metrics collection")
		noAllocationsMetricsEnabled     = flag.Bool("no-allocations-metrics", false, "disable allocations metrics collection")
		noEvalMetricsEnabled            = flag.Bool("no-eval-metrics", false, "disable eval metrics collection")
		noDeploymentMetricsEnabled      = flag.Bool("no-deployment-metrics", false, "disable deployment metrics collection")
		noAllocationStatsMetricsEnabled = flag.Bool("no-allocation-stats-metrics", false, "disable stats metrics collection")
		concurrency                     = flag.Int("concurrency", 20, "max number of goroutines to launch concurrently when poking the API")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.GetVersion())
		os.Exit(0)
	}

	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	cfg := api.DefaultConfig()
	cfg.Address = *nomadServer

	cfg.HttpClient.Timeout = time.Duration(*nomadTimeout) * time.Millisecond

	waitTime := time.Duration(*nomadWaitTime) * time.Millisecond
	cfg.WaitTime = waitTime

	if strings.HasPrefix(cfg.Address, "https://") {
		cfg.TLSConfig.CACert = *tlsCaFile
		cfg.TLSConfig.CAPath = *tlsCaPath
		cfg.TLSConfig.ClientKey = *tlsKey
		cfg.TLSConfig.ClientCert = *tlsCert
		cfg.TLSConfig.Insecure = *tlsInsecure
		cfg.TLSConfig.TLSServerName = *tlsServerName
	}

	apiClient, err := api.NewClient(cfg)
	if err != nil {
		logrus.Fatalf("could not create exporter: %s", err)
	}

	exporter := &Exporter{
		client:                        apiClient,
		AllowStaleReads:               *allowStaleReads,
		PeerMetricsEnabled:            !*noPeerMetricsEnabled,
		SerfMetricsEnabled:            !*noSerfMetricsEnabled,
		NodeMetricsEnabled:            !*noNodeMetricsEnabled,
		JobMetricEnabled:              !*noJobMetricsEnabled,
		AllocationsMetricsEnabled:     !*noAllocationsMetricsEnabled,
		EvalMetricsEnabled:            !*noEvalMetricsEnabled,
		DeploymentMetricsEnabled:      !*noDeploymentMetricsEnabled,
		AllocationStatsMetricsEnabled: !*noAllocationStatsMetricsEnabled,
		Concurrency:                   *concurrency,
	}

	logrus.Debugf("Created exporter %#v", *exporter)

	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Nomad Exporter</title></head>
             <body>
             <h1>Nomad Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	logrus.Println("Listening on", *listenAddress)
	logrus.Fatal(http.ListenAndServe(*listenAddress, nil))
}
