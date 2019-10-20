#!/bin/sh

if [ -f /etc/ssl/certs/nomad/nomad_ca_bundle.pem ]; then
	/bin/rm -f /etc/ssl/certs/nomad_ca_bundle.pem
	/bin/ln -s nomad/nomad_ca_bundle.pem /etc/ssl/certs
	/usr/sbin/update-ca-certificates
fi

exec /nomad-exporter $@
