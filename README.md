# Nomad Prometheus Exporter

Originally a fork of Nomon/nomad-exporter, now an extended version of it.

## Docker

```bash
docker run pcarranza/nomad-exporter:latest
```

## Nomad version

Currently supporting Nomad 0.8.3 API version

## Leader Detection

The way to identify the leader is by comparing the leader address obtained
through the API call with the client address, if they both aim for the same
hostname, then the reading exporter is considered to be reading from the
leader host.

If you are having problems identifying the leader, use `-debug` to read what
data the current exporter is handling.

## Allow Reading Stale Metrics

By default  exporter will try to identify the leader of the cluster and
only get metrics from it.

This is a defense mechanism to prevent impacting the whole cluster by
requesting every node with metrics from everybody else.

Still, there's a `-allow-stale-reads` argument that can be used to enable
recording metrics from any hosts regardless of it being the leader or not.

## Exported Metrics

| Metric | Meaning | Labels |
| ------ | ------- | ------ |
|nomad_up | Wether the exporter is able to talk to the nomad server. | |
|nomad_client_api_errors_total | Number of errors that this exporter had when querying the API. | |
|nomad_leader | Wether the current host is the cluster leader. | |
|nomad_jobs | How many jobs are there in the cluster. | |
|nomad_node_info | Node information. | name, version, class, status, drain, datacenter, scheduling_eligibility |
|nomad_raft_peers | How many peers (servers) are in the Raft cluster. | |
|nomad_serf_lan_members | How many members are in the cluster. | |
|serf_lan_member_status_info | Describes member state. | datacenter, class, node, drain |
|nomad_allocation | Allocation labeled with runtime information. | status, desired_status, job_type, job_id, task_group, node |
|nomad_evals | The number of evaluations. | status |
|nomad_tasks | The number of tasks. | state, failed, job_type, node |
|nomad_deployments | The number of deployments. | status, job_id |
|nomad_deployment_task_group_desired_canaries | The number of desired canaries for the task group. | job_id, deployment_id, task_group, promoted, auto_revert |
|nomad_deployment_task_group_desired | The number of desired allocs for the task group. | job_id, deployment_id, task_group, promoted, auto_revert |
|nomad_deployment_task_group_healthy_allocs | The number of healthy allocs for the task group. | job_id, deployment_id, task_group, promoted, auto_revert |
|nomad_deployment_task_group_placed_allocs | The number of placed allocs for the task group. | job_id, deployment_id, task_group, promoted, auto_revert |
|nomad_deployment_task_group_unhealthy_allocs | The number of unhealthy allocs for the task group. | job_id, deployment_id, task_group, promoted, auto_revert |
|nomad_allocation_memory_rss_bytes | Allocation memory usage. | job, group, alloc, region, datacenter, node |
|nomad_allocation_memory_rss_limit_bytes | Allocation memory limit. | job, group, alloc, region, datacenter, node |
|nomad_allocation_cpu_percent | Allocation CPU usage. | job, group, alloc, region, datacenter, node |
|nomad_allocation_cpu_throttle_time | Allocation throttled CPU. | job, group, alloc, region, datacenter, node |
|nomad_task_cpu_total_ticks | Task CPU total ticks. | job, group, alloc, region, datacenter, node, task |
|nomad_task_cpu_percent | Task CPU usage percent. | job, group, alloc, region, datacenter, node, task |
|nomad_task_memory_rss_bytes | Task memory RSS usage in bytes. | job, group, alloc, region, datacenter, node, task |
|nomad_node_resource_memory_bytes | Amount of allocatable memory the node has in bytes| node, datacenter |
|nomad_node_allocated_memory_bytes | Amount of memory allocated to tasks on the node in bytes. | node, datacenter |
|nomad_node_used_memory_bytes | Amount of memory used on the node in bytes. | node, datacenter |
|nomad_node_resource_cpu_megahertz | Amount of allocatable CPU the node has in MHz. | node, datacenter |
|nomad_node_resource_iops | Amount of allocatable IOPS the node has. | node, datacenter |
|nomad_node_resource_disk_bytes | Amount of allocatable disk bytes the node has. | node, datacenter |
|nomad_node_allocated_cpu_megahertz | Amount of allocated CPU on the node in MHz. | node, datacenter |
|nomad_node_used_cpu_megahertz | Amount of CPU used on the node in MHz. | node, datacenter |

## Usage

* -allow-stale-reads: allow to read metrics from a non-leader server
* -debug: enable debug log level
* -nomad.server string: HTTP API address of a Nomad server or agent. (default "http://localhost:4646")
* -nomad.timeout int: HTTP timeout to contact Nomad agent, or read from it. (default 10)
* -tls.ca-file string: ca-file path to a PEM-encoded CA cert file to use to verify the connection to nomad server
* -tls.ca-path string: ca-path is the path to a directory of PEM-encoded CA cert files to verify the connection to nomad server
* -tls.cert-file string: cert-file is the path to the client certificate for Nomad communication
* -tls.insecure: insecure enables or disables SSL verification
* -tls.key-file string: key-file is the path to the key for cert-file
* -tls.tls-server-name string: tls-server-name sets the SNI for Nomad ssl connection
* -version: Print version information.
* -web.listen-address string: Address to listen on for web interface and telemetry. (default ":9172")
* -web.telemetry-path string: Path under which to expose metrics. (default "/metrics")
