package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	go_ver "github.com/hashicorp/go-version"
	"github.com/hashicorp/nomad/api"
	"github.com/pcarranza/nomad-exporter/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	namespace = "nomad"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Wether the exporter is able to talk to the nomad server.",
		nil, nil,
	)
	clientErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "client_errors_total",
			Help:      "Number of errors that were accounted for.",
		})
	clusterLeader = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "leader"),
		"Wether the current host is the cluster leader.",
		nil, nil)
	clusterServers = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "raft_peers"),
		"How many peers (servers) are in the Raft cluster.",
		nil, nil,
	)
	nodeInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_info"),
		"Node information",
		[]string{"name", "version", "class", "status", "drain", "datacenter", "scheduling_eligibility"},
		nil,
	)
	serfLanMembers = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "serf_lan_members"),
		"How many members are in the cluster.",
		nil, nil,
	)
	serfLanMembersStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "serf_lan_member_status"),
		"Describe member state.",
		[]string{"datacenter", "class", "node", "drain"}, nil,
	)
	jobsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jobs_total"),
		"How many jobs are there in the cluster.",
		nil, nil,
	)
	allocationMemoryBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_memory_rss_bytes"),
		"Allocation memory usage",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationMemoryBytesRequired = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_memory_rss_required_bytes"),
		"Allocation memory required.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPURequired = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_required"),
		"Allocation CPU Required.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPUPercent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_percent"),
		"Allocation CPU usage.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPUTicks = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_ticks"),
		"Allocation CPU Ticks usage.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPUUserMode = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_user_mode"),
		"Allocation CPU User Mode Usage.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPUSystemMode = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_system_mode"),
		"Allocation CPU System Mode Usage.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	allocationCPUThrottled = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "allocation_cpu_throttle_time"),
		"Allocation throttled CPU.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node"}, nil,
	)
	taskCPUTotalTicks = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "task_cpu_total_ticks"),
		"Task CPU total ticks.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node", "task"}, nil,
	)
	taskCPUPercent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "task_cpu_percent"),
		"Task CPU usage percent.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node", "task"}, nil,
	)
	taskMemoryRssBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "task_memory_rss_bytes"),
		"Task memory RSS usage in bytes.",
		[]string{"job", "group", "alloc", "region", "datacenter", "node", "task"}, nil,
	)

	nodeResourceMemory = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_resource_memory_bytes"),
		"Amount of allocatable memory the node has in bytes",
		[]string{"node", "datacenter"}, nil,
	)
	nodeAllocatedMemory = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_allocated_memory_bytes"),
		"Amount of memory allocated to tasks on the node in bytes.",
		[]string{"node", "datacenter"}, nil,
	)
	nodeUsedMemory = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_used_memory_bytes"),
		"Amount of memory used on the node in bytes.",
		[]string{"node", "datacenter"}, nil,
	)
	nodeResourceCPU = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_resource_cpu_megahertz"),
		"Amount of allocatable CPU the node has in MHz",
		[]string{"node", "datacenter"}, nil,
	)
	nodeResourceIOPS = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_resource_iops"),
		"Amount of allocatable IOPS the node has.",
		[]string{"node", "datacenter"}, nil,
	)
	nodeResourceDiskBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_resource_disk_bytes"),
		"Amount of allocatable disk bytes the node has.",
		[]string{"node", "datacenter"}, nil,
	)
	nodeAllocatedCPU = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_allocated_cpu_megahertz"),
		"Amount of allocated CPU on the node in MHz.",
		[]string{"node", "datacenter"}, nil,
	)
	nodeUsedCPU = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "node_used_cpu_megahertz"),
		"Amount of CPU used on the node in MHz.",
		[]string{"node", "datacenter"}, nil,
	)

	allocation = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "allocation",
		Help:      "Allocation labeled with runtime information.",
	},
		[]string{
			"status",
			"desired_status",
			"job_type",
			"job_id",
			"task_group",
			"node",
		},
	)
	evalCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "evals_total",
		Help:      "The number of evaluations.",
	},
		[]string{"status"},
	)
	taskCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "tasks_total",
		Help:      "The number of tasks.",
	},
		[]string{
			"state",
			"failed",
			"job_type",
			"node",
		},
	)

	deploymentCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployments_total",
		Help:      "The number of deployments.",
	},
		[]string{
			"status",
			"job_id",
		},
	)

	deploymentTaskGroupDesiredCanaries = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployment_task_group_desired_canaries_total",
		Help:      "The number of desired canaries for the task group.",
	},
		[]string{
			"job_id",
			"deployment_id",
			"task_group",
			"promoted",
			"auto_revert",
		},
	)

	deploymentTaskGroupDesiredTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployment_task_group_desired_total",
		Help:      "The number of desired allocs for the task group.",
	},
		[]string{
			"job_id",
			"deployment_id",
			"task_group",
			"promoted",
			"auto_revert",
		},
	)

	deploymentTaskGroupPlacedAllocs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployment_task_group_placed_allocs_total",
		Help:      "The number of placed allocs for the task group.",
	},
		[]string{
			"job_id",
			"deployment_id",
			"task_group",
			"promoted",
			"auto_revert",
		},
	)

	deploymentTaskGroupHealthyAllocs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployment_task_group_healthy_allocs_total",
		Help:      "The number of healthy allocs for the task group.",
	},
		[]string{
			"job_id",
			"deployment_id",
			"task_group",
			"promoted",
			"auto_revert",
		},
	)

	deploymentTaskGroupUnhealthyAllocs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "deployment_task_group_unhealthy_allocs_total",
		Help:      "the number of unhealthy allocs for the task group",
	},
		[]string{
			"job_id",
			"deployment_id",
			"task_group",
			"promoted",
			"auto_revert",
		},
	)

	apiLatencySummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Namespace: namespace,
		Name:      "api_latency_seconds",
		Help:      "nomad api latency for different queries",
	},
		[]string{
			"query",
		})
	apiNodeLatencySummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Namespace: namespace,
		Name:      "api_node_latency_seconds",
		Help:      "nomad api latency for different nodes and queries",
	},
		[]string{
			"node",
			"query",
		})
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
			"nomad.timeout", 10, "HTTP timeout to contact Nomad agent, or read from it.")
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

	timeout := time.Duration(*nomadTimeout) * time.Second

	if err := cfg.SetTimeout(time.Duration(*nomadTimeout) * time.Second); err != nil {
		logrus.Fatalf("failed to set timeout: %s", err)
	}
	cfg.WaitTime = timeout

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

var minVersion *go_ver.Version

func init() {
	m, err := go_ver.NewVersion("0.8")
	if err != nil {
		logrus.Fatalf("failed to parse the minimum version: %s", err)
	}
	minVersion = m
}

func logError(err error) {
	clientErrors.Inc()
	logrus.Error(err)
}

func validVersion(name, ver string) bool {
	nodeVersion, err := go_ver.NewVersion(ver)
	if err != nil {
		logrus.Errorf("can't parse node %s version %s: %s", name, ver, err)
		return false
	}
	if nodeVersion.LessThan(minVersion) {
		logrus.Debugf("Skipping node %s because it has version %s", name, ver)
		return false
	}
	return true
}

func measure(query string, f func() error) error {
	o := newLatencyObserver(query)
	err := f()
	o.observe()
	return err
}

type latencyObserver struct {
	startTime time.Time
	node      string
	query     string
}

func newLatencyObserver(query string) latencyObserver {
	return latencyObserver{
		node:      "",
		query:     query,
		startTime: time.Now(),
	}
}

func newNodeLatencyObserver(node, query string) latencyObserver {
	return latencyObserver{
		node:      node,
		query:     query,
		startTime: time.Now(),
	}
}

func (n latencyObserver) observe() {
	duration := time.Since(n.startTime)

	if n.node == "" {
		apiLatencySummary.WithLabelValues(n.query).Observe(duration.Seconds())
		logrus.Debugf("Duration for query %s: %f", n.query, duration.Seconds())
	} else {
		apiNodeLatencySummary.WithLabelValues(n.node, n.query).Observe(duration.Seconds())
		logrus.Debugf("Duration for node %s, query %s: %f", n.query, n.node, duration.Seconds())
	}
}
