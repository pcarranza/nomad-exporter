package main

import "flag"
import "os"

type args struct {
	ShowVersion                     bool
	ListenAddress                   string
	MetricsPath                     string
	NomadAddress                    string
	NomadTimeout                    int
	NomadWaitTime                   int
	TLSCaFile                       string
	TLSCaPath                       string
	TLSCert                         string
	TLSKey                          string
	TLSInsecure                     bool
	TLSServerName                   string
	Debug                           bool
	AllowStaleReads                 bool
	NoPeerMetricsEnabled            bool
	NoSerfMetricsEnabled            bool
	NoNodeMetricsEnabled            bool
	NoJobMetricsEnabled             bool
	NoAllocationsMetricsEnabled     bool
	NoEvalMetricsEnabled            bool
	NoDeploymentMetricsEnabled      bool
	NoAllocationStatsMetricsEnabled bool
	Concurrency                     int
}

func parseArgs() args {
	var a args

	flag.BoolVar(&a.ShowVersion, "version", false, "Print version information.")
	flag.BoolVar(&a.Debug, "debug", false, "enable debug log level")

	flag.StringVar(&a.ListenAddress,
		"web.listen-address", ":9441", "Address to listen on for web interface and telemetry.")
	flag.StringVar(&a.MetricsPath,
		"web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	nomad_addr := os.Getenv("NOMAD_ADDR")
	if len(nomad_addr) == 0 {
		nomad_addr = "http://localhost:4646"
	}
	flag.StringVar(&a.NomadAddress,
		"nomad.address", nomad_addr, "HTTP API address of a Nomad server or agent.")
	flag.IntVar(&a.NomadTimeout,
		"nomad.timeout", 500, "HTTP read timeout when talking to the Nomad agent. In milliseconds")
	flag.IntVar(&a.NomadWaitTime,
		"nomad.waittime", 10, "Timeout to wait for the Nomad agent to deliver fresh data. In milliseconds.")

	tls_ca_file := os.Getenv("NOMAD_CACERT")
	flag.StringVar(&a.TLSCaFile,
		"tls.ca-file", tls_ca_file, "ca-file path to a PEM-encoded CA cert file to use to verify the connection to nomad server")
	tls_ca_path := os.Getenv("NOMAD_CAPATH")
	flag.StringVar(&a.TLSCaPath,
		"tls.ca-path", tls_ca_path, "ca-path is the path to a directory of PEM-encoded CA cert files to verify the connection to nomad server")
	tls_cert_file := os.Getenv("NOMAD_CLIENT_CERT")
	flag.StringVar(&a.TLSCert,
		"tls.cert-file", tls_cert_file, "cert-file is the path to the client certificate for Nomad communication")
	tls_cert_key := os.Getenv("NOMAD_CLIENT_KEY")
	flag.StringVar(&a.TLSKey,
		"tls.key-file", tls_cert_key, "key-file is the path to the key for cert-file")
	tls_skip_verify := os.Getenv("NOMAD_SKIP_VERIFY")
	flag.BoolVar(&a.TLSInsecure,
		"tls.insecure", len(tls_skip_verify) > 0, "insecure enables or disables SSL verification")
	flag.StringVar(&a.TLSServerName,
		"tls.tls-server-name", "", "tls-server-name sets the SNI for Nomad ssl connection")

	flag.BoolVar(&a.AllowStaleReads, "allow-stale-reads", false, "allow to read metrics from a non-leader server")

	flag.BoolVar(&a.NoPeerMetricsEnabled, "no-peer-metrics", false, "disable peer metrics collection")
	flag.BoolVar(&a.NoSerfMetricsEnabled, "no-serf-metrics", false, "disable serf metrics collection")
	flag.BoolVar(&a.NoNodeMetricsEnabled, "no-node-metrics", false, "disable node metrics collection")
	flag.BoolVar(&a.NoJobMetricsEnabled, "no-jobs-metrics", false, "disable jobs metrics collection")
	flag.BoolVar(&a.NoAllocationsMetricsEnabled, "no-allocations-metrics", false, "disable allocations metrics collection")
	flag.BoolVar(&a.NoEvalMetricsEnabled, "no-eval-metrics", false, "disable eval metrics collection")
	flag.BoolVar(&a.NoDeploymentMetricsEnabled, "no-deployment-metrics", false, "disable deployment metrics collection")
	flag.BoolVar(&a.NoAllocationStatsMetricsEnabled, "no-allocation-stats-metrics", false, "disable stats metrics collection")
	flag.IntVar(&a.Concurrency, "concurrency", 20, "max number of goroutines to launch concurrently when poking the API")

	flag.Parse()

	return a
}
