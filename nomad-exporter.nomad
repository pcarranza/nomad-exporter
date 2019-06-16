job "nomad-exporter" {
	datacenters = ["dc1"]

	# Configure the job to do rolling updates
	update {
		stagger          = "10s"
		max_parallel     = 1
		canary           = 1
		min_healthy_time = "5s"
		healthy_deadline = "15s"
	}

	group "nomad-exporter-group" {
		count = 1

		restart {
			attempts = 2
			interval = "1m"
			delay = "10s"
			mode = "fail"
		}

		# Define a task to run
		task "nomad-exporter" {
			driver = "docker"
			config {
				image = "registry.gitlab.com/yakshaving.art/nomad-exporter:latest"
				port_map {
					http = 9441
				}
				args = [
					"-allow-stale-reads",
					"-nomad.address",
					"http://${attr.nomad.advertise.address}",
				]
			}

			service {
				name = "${TASK}-service"
				tags = ["nomad-exporter"]
				port = "http"
				check {
					name = "alive"
					type = "http"
					interval = "15s"
					timeout = "5s"
					path = "/status"
				}
			}

			resources {
				cpu = 100 # MHz
				memory = 64 # MB
				network {
					mbits = 1
					port "http" { }
				}
			}

			# Specify configuration related to log rotation
			logs {
			    max_files = 10
			    max_file_size = 15
			}

			# Controls the timeout between signalling a task it will be killed
			# and killing the task. If not set a default is used.
			kill_timeout = "3s"
		}
  }
}
