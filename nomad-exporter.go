package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
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

// Exporter is a nomad exporter
type Exporter struct {
	client                        *api.Client
	AllowStaleReads               bool
	amILeader                     bool
	PeerMetricsEnabled            bool
	NodeMetricsEnabled            bool
	JobMetricEnabled              bool
	AllocationsMetricsEnabled     bool
	EvalMetricsEnabled            bool
	DeploymentMetricsEnabled      bool
	AllocationStatsMetricsEnabled bool
	Concurrency                   int
}

func (e *Exporter) shouldReadMetrics() bool {
	return e.amILeader || e.AllowStaleReads
}

// Describe implements Collector interface.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- nodeInfo
	ch <- clusterServers
	ch <- serfLanMembers
	ch <- serfLanMembersStatus
	ch <- jobsTotal
	ch <- allocationMemoryBytes
	ch <- allocationCPUPercent
	ch <- allocationCPUTicks
	ch <- allocationCPUUserMode
	ch <- allocationCPUSystemMode
	ch <- allocationCPUThrottled
	ch <- allocationMemoryBytesRequired
	ch <- allocationCPURequired
	ch <- taskCPUPercent
	ch <- taskCPUTotalTicks
	ch <- taskMemoryRssBytes
	ch <- nodeResourceMemory
	ch <- nodeAllocatedMemory
	ch <- nodeUsedMemory
	ch <- nodeResourceCPU
	ch <- nodeResourceIOPS
	ch <- nodeResourceDiskBytes
	ch <- nodeAllocatedCPU
	ch <- nodeUsedCPU

	allocation.Describe(ch)
	evalCount.Describe(ch)
	taskCount.Describe(ch)

	deploymentCount.Describe(ch)

	deploymentTaskGroupDesiredCanaries.Describe(ch)
	deploymentTaskGroupDesiredTotal.Describe(ch)
	deploymentTaskGroupPlacedAllocs.Describe(ch)
	deploymentTaskGroupHealthyAllocs.Describe(ch)
	deploymentTaskGroupUnhealthyAllocs.Describe(ch)

	clientErrors.Describe(ch)
	apiLatencySummary.Describe(ch)
	apiNodeLatencySummary.Describe(ch)
}

// Collect collects nomad metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	if err := measure("leader", func() error {
		return e.collectLeader(ch)
	}); err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		logError(err)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)

	ch <- clientErrors

	if e.PeerMetricsEnabled {
		if err := measure("peers", func() error { return e.collectPeerMetrics(ch) }); err != nil {
			logError(err)
			return
		}
	}

	if e.NodeMetricsEnabled {
		if err := measure("nodes", func() error { return e.collectNodes(ch) }); err != nil {
			logError(err)
			return
		}
	}

	if e.JobMetricEnabled {
		if err := measure("jobs", func() error { return e.collectJobsMetrics(ch) }); err != nil {
			logError(err)
			return
		}
	}

	if e.AllocationsMetricsEnabled {
		if err := measure("allocations", func() error { return e.collectAllocations(ch) }); err != nil {
			logError(err)
			return
		}
	}

	if e.EvalMetricsEnabled {
		if err := measure("eval", func() error { return e.collectEvalMetrics(ch) }); err != nil {
			logError(err)
			return
		}
	}

	if e.DeploymentMetricsEnabled {
		if err := measure("deployment", func() error { return e.collectDeploymentMetrics(ch) }); err != nil {
			logError(err)
			return
		}
	}

	apiLatencySummary.Collect(ch)
	apiNodeLatencySummary.Collect(ch)
}

func (e *Exporter) collectLeader(ch chan<- prometheus.Metric) error {
	leader, err := e.client.Status().Leader()
	if err != nil {
		return fmt.Errorf("could not collect leader: %s", err)
	}

	logrus.Debugf("Leader is %s", leader)
	logrus.Debugf("Client address is %s", e.client.Address())

	leaderHostname, _, err := net.SplitHostPort(leader)
	if err != nil {
		return fmt.Errorf("leader is not a host:port but %s: %s", leader, err)
	}

	clientHost, err := url.Parse(e.client.Address())
	if err != nil {
		return fmt.Errorf("client address %s can't be parsed as a url: %s", e.client.Address(), err)
	}

	logrus.Debugf("Client Hostname is %s", clientHost.Hostname())
	logrus.Debugf("Leader Hostname is %s", leaderHostname)

	var isLeader float64
	if leaderHostname == clientHost.Hostname() {
		isLeader = 1
	}

	e.amILeader = isLeader == 1

	ch <- prometheus.MustNewConstMetric(
		clusterLeader, prometheus.GaugeValue, isLeader,
	)
	return nil
}

func (e *Exporter) collectJobsMetrics(ch chan<- prometheus.Metric) error {
	if !e.shouldReadMetrics() {
		return nil
	}

	jobs, _, err := e.client.Jobs().List(&api.QueryOptions{
		AllowStale: true,
	})
	if err != nil {
		return fmt.Errorf("could not get jobs: %s", err)
	}
	logrus.Debugf("collected job metrics %d", len(jobs))
	ch <- prometheus.MustNewConstMetric(
		jobsTotal, prometheus.GaugeValue, float64(len(jobs)),
	)
	return nil
}

func (e *Exporter) collectNodes(ch chan<- prometheus.Metric) error {
	if !e.shouldReadMetrics() {
		return nil
	}

	opts := &api.QueryOptions{
		AllowStale: true,
	}

	o := newLatencyObserver("list_nodes")
	nodes, _, err := e.client.Nodes().List(opts)
	o.observe()
	if err != nil {
		return fmt.Errorf("failed to get nodes list: %s", err)
	}
	ch <- prometheus.MustNewConstMetric(
		serfLanMembers, prometheus.GaugeValue, float64(len(nodes)),
	)
	logrus.Debugf("I've the nodes list with %d nodes", len(nodes))

	var w sync.WaitGroup
	pool := make(chan func(), e.Concurrency)
	go func() {
		for f := range pool {
			go f()
		}
	}()

	for _, node := range nodes {
		w.Add(1)
		pool <- func(node api.NodeListStub) func() {
			return func() {
				defer w.Done()
				state := 1
				drain := strconv.FormatBool(node.Drain)

				ch <- prometheus.MustNewConstMetric(
					nodeInfo, prometheus.GaugeValue, 1,
					node.Name, node.Version, node.NodeClass, node.Status,
					drain, node.Datacenter, node.SchedulingEligibility,
				)

				if node.Status == "down" {
					state = 0
				}
				ch <- prometheus.MustNewConstMetric(
					serfLanMembersStatus, prometheus.GaugeValue, float64(state),
					node.Datacenter, node.NodeClass, node.Name, drain,
				)

				if node.Status != "ready" {
					logrus.Debugf("Skipping node information and allocations %s because it is %s", node.Name, node.Status)
					return
				}

				if !validVersion(node.Name, node.Version) {
					return
				}

				if !e.AllocationStatsMetricsEnabled {
					return
				}

				logrus.Debugf("Fetching node %#v", node)
				o := newNodeLatencyObserver(node.Name, "fetch_node")
				node, _, err := e.client.Nodes().Info(node.ID, opts)
				o.observe()
				if err != nil {
					logError(fmt.Errorf("Failed to get node %s info: %s", node.Name, err))
					return
				}

				logrus.Debugf("Node %s fetched", node.Name)

				o = newNodeLatencyObserver(node.Name, "get_running_allocs")
				runningAllocs, err := e.getRunningAllocs(node.ID)
				o.observe()
				if err != nil {
					logError(fmt.Errorf("failed to get node %s running allocs: %s", node.Name, err))
					return
				}

				var allocatedCPU, allocatedMemory int
				for _, alloc := range runningAllocs {
					allocatedCPU += *alloc.Resources.CPU
					allocatedMemory += *alloc.Resources.MemoryMB
				}

				nodeLabels := []string{node.Name, node.Datacenter}
				ch <- prometheus.MustNewConstMetric(
					nodeResourceMemory, prometheus.GaugeValue, float64(*node.Resources.MemoryMB)*1024*1024,
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeAllocatedMemory, prometheus.GaugeValue, float64(allocatedMemory)*1024*1024,
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeAllocatedCPU, prometheus.GaugeValue, float64(allocatedCPU),
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeResourceCPU, prometheus.GaugeValue, float64(*node.Resources.CPU),
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeResourceIOPS, prometheus.GaugeValue, float64(*node.Resources.IOPS),
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeResourceDiskBytes, prometheus.GaugeValue, float64(*node.Resources.DiskMB)*1024*1024,
					nodeLabels...,
				)

				o = newNodeLatencyObserver(node.Name, "get_stats")
				nodeStats, err := e.client.Nodes().Stats(node.ID, opts)
				o.observe()
				if err != nil {
					logError(fmt.Errorf("failed to get node %s stats: %s", node.Name, err))
					return
				}
				logrus.Debugf("Fetched node %s stats", node.Name)

				ch <- prometheus.MustNewConstMetric(
					nodeUsedMemory, prometheus.GaugeValue, float64(nodeStats.Memory.Used)*1024*1024,
					nodeLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					nodeUsedCPU, prometheus.GaugeValue, float64(math.Floor(nodeStats.CPUTicksConsumed)),
					nodeLabels...,
				)
			}
		}(*node)
	}

	w.Wait()

	logrus.Debugf("done waiting for node metrics")
	return nil
}

func (e *Exporter) getRunningAllocs(nodeID string) ([]*api.Allocation, error) {
	var allocs []*api.Allocation

	// Query the node allocations
	nodeAllocs, _, err := e.client.Nodes().Allocations(nodeID, nil)

	// Filter list to only running allocations
	for _, alloc := range nodeAllocs {
		if alloc.ClientStatus == "running" {
			allocs = append(allocs, alloc)
		}
	}
	return allocs, err
}

func (e *Exporter) collectPeerMetrics(ch chan<- prometheus.Metric) error {
	if !e.shouldReadMetrics() {
		return nil
	}

	peers, err := e.client.Status().Peers()
	if err != nil {
		return fmt.Errorf("failed to get peer metrics: %s", err)
	}
	ch <- prometheus.MustNewConstMetric(
		clusterServers, prometheus.GaugeValue, float64(len(peers)),
	)
	return nil
}

func (e *Exporter) collectAllocations(ch chan<- prometheus.Metric) error {
	allocation.Reset()
	taskCount.Reset()

	if !e.shouldReadMetrics() {
		return nil
	}

	o := newLatencyObserver("get_allocations")
	allocStubs, _, err := e.client.Allocations().List(&api.QueryOptions{
		AllowStale: true,
	})
	o.observe()
	if err != nil {
		return fmt.Errorf("could not get allocations: %s", err)
	}

	var w sync.WaitGroup

	for _, allocStub := range allocStubs {
		w.Add(1)

		go func(allocStub api.AllocationListStub) {
			defer w.Done()

			o := newLatencyObserver("get_allocation_node")
			node, _, err := e.client.Nodes().Info(allocStub.NodeID, &api.QueryOptions{
				AllowStale: true,
			})
			o.observe()
			if err != nil {
				logError(err)
				return
			}

			if node.Status != "ready" {
				logrus.Debugf("Skipping fetching allocation %s for node %s because it's not in ready state but %s",
					allocStub.Name, node.Name, node.Status)
				return
			}
			v := node.Attributes["nomad.version"]
			if !validVersion(node.Name, v) {
				return
			}

			o = newLatencyObserver("get_allocation_info")
			alloc, _, err := e.client.Allocations().Info(allocStub.ID, &api.QueryOptions{
				AllowStale: true,
			})
			o.observe()
			if err != nil {
				logError(err)
				return
			}

			job := alloc.Job

			allocation.With(prometheus.Labels{
				"status":         alloc.ClientStatus,
				"desired_status": alloc.DesiredStatus,
				"job_type":       *job.Type,
				"job_id":         alloc.JobID,
				"task_group":     alloc.TaskGroup,
				"node":           node.Name,
			}).Add(1)

			taskStates := alloc.TaskStates

			for _, task := range taskStates {
				taskCount.With(prometheus.Labels{
					"state":    task.State,
					"failed":   strconv.FormatBool(task.Failed),
					"job_type": *job.Type,
					"node":     node.Name,
				}).Add(1)
			}

			// Return unless the allocation is running
			if allocStub.ClientStatus != "running" {
				return
			}

			no := newNodeLatencyObserver(node.Name, "get_allocation_stats")
			stats, err := e.client.Allocations().Stats(alloc, &api.QueryOptions{})
			no.observe()
			if err != nil {
				logError(err)
				return
			}

			allocationLabels := []string{
				*alloc.Job.Name,
				alloc.TaskGroup,
				alloc.Name,
				*alloc.Job.Region,
				node.Datacenter,
				node.Name,
			}
			ch <- prometheus.MustNewConstMetric(
				allocationCPUPercent, prometheus.GaugeValue, stats.ResourceUsage.CpuStats.Percent, allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationCPUThrottled, prometheus.GaugeValue, float64(stats.ResourceUsage.CpuStats.ThrottledTime), allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationMemoryBytes, prometheus.GaugeValue, float64(stats.ResourceUsage.MemoryStats.RSS), allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationCPUTicks, prometheus.GaugeValue, float64(stats.ResourceUsage.CpuStats.TotalTicks), allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationCPUUserMode, prometheus.GaugeValue, float64(stats.ResourceUsage.CpuStats.UserMode), allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationCPUSystemMode, prometheus.GaugeValue, float64(stats.ResourceUsage.CpuStats.SystemMode), allocationLabels...,
			)

			ch <- prometheus.MustNewConstMetric(
				allocationMemoryBytesRequired, prometheus.GaugeValue, float64(*alloc.Resources.MemoryMB)*1024*1024, allocationLabels...,
			)
			ch <- prometheus.MustNewConstMetric(
				allocationCPURequired, prometheus.GaugeValue, float64(*alloc.Resources.CPU), allocationLabels...,
			)

			for taskName, taskStats := range stats.Tasks {
				taskLabels := append(allocationLabels, taskName)
				ch <- prometheus.MustNewConstMetric(
					taskCPUPercent, prometheus.GaugeValue, taskStats.ResourceUsage.CpuStats.Percent, taskLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					taskCPUTotalTicks, prometheus.GaugeValue, taskStats.ResourceUsage.CpuStats.TotalTicks, taskLabels...,
				)
				ch <- prometheus.MustNewConstMetric(
					taskMemoryRssBytes, prometheus.GaugeValue, float64(taskStats.ResourceUsage.MemoryStats.RSS), taskLabels...,
				)
			}

		}(*allocStub)
	}

	w.Wait()

	allocation.Collect(ch)
	taskCount.Collect(ch)
	return nil
}

func (e *Exporter) collectEvalMetrics(ch chan<- prometheus.Metric) error {
	evalCount.Reset()

	if !e.shouldReadMetrics() {
		return nil
	}

	evals, _, err := e.client.Evaluations().List(&api.QueryOptions{
		AllowStale: true,
	})
	if err != nil {
		return fmt.Errorf("could not get evaluation metrics: %s", err)
	}

	for _, eval := range evals {
		evalCount.With(prometheus.Labels{
			"status": eval.Status,
		}).Add(1)
	}

	evalCount.Collect(ch)

	return nil
}

func (e *Exporter) collectDeploymentMetrics(ch chan<- prometheus.Metric) error {
	deploymentCount.Reset()
	deploymentTaskGroupDesiredCanaries.Reset()
	deploymentTaskGroupDesiredTotal.Reset()
	deploymentTaskGroupPlacedAllocs.Reset()
	deploymentTaskGroupHealthyAllocs.Reset()
	deploymentTaskGroupUnhealthyAllocs.Reset()

	if !e.shouldReadMetrics() {
		return nil
	}

	deployments, _, err := e.client.Deployments().List(&api.QueryOptions{
		AllowStale: true,
	})
	if err != nil {
		return err
	}

	for _, dep := range deployments {
		taskGroups := dep.TaskGroups

		deploymentCount.With(prometheus.Labels{
			"status": dep.Status,
			"job_id": dep.JobID,
		}).Add(1)

		for taskGroupName, taskGroup := range taskGroups {
			deploymentLabels := []string{
				dep.JobID,
				dep.ID,
				taskGroupName,
				strconv.FormatBool(taskGroup.Promoted),
				strconv.FormatBool(taskGroup.AutoRevert),
			}

			deploymentTaskGroupDesiredCanaries.WithLabelValues(
				deploymentLabels...).Set(float64(taskGroup.DesiredCanaries))
			deploymentTaskGroupDesiredTotal.WithLabelValues(
				deploymentLabels...).Set(float64(taskGroup.DesiredTotal))
			deploymentTaskGroupPlacedAllocs.WithLabelValues(
				deploymentLabels...).Set(float64(taskGroup.PlacedAllocs))
			deploymentTaskGroupHealthyAllocs.WithLabelValues(
				deploymentLabels...).Set(float64(taskGroup.HealthyAllocs))
			deploymentTaskGroupUnhealthyAllocs.WithLabelValues(
				deploymentLabels...).Set(float64(taskGroup.UnhealthyAllocs))
		}
	}

	deploymentCount.Collect(ch)
	deploymentTaskGroupDesiredCanaries.Collect(ch)
	deploymentTaskGroupDesiredTotal.Collect(ch)
	deploymentTaskGroupPlacedAllocs.Collect(ch)
	deploymentTaskGroupHealthyAllocs.Collect(ch)
	deploymentTaskGroupUnhealthyAllocs.Collect(ch)

	return nil
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
