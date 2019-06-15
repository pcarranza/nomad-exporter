# Makefile for gitlab group manager
# vim: set ft=make ts=8 noet
# Copyright Yakshaving.art
# Licence MIT

# Variables
# UNAME		:= $(shell uname -s)

src = $(wildcard *.go)

COMMIT_ID := `git log -1 --format=%H`
COMMIT_DATE := `git log -1 --format=%aI`
VERSION := $${CI_COMMIT_TAG:-SNAPSHOT-$(COMMIT_ID)}

# this is godly
# https://news.ycombinator.com/item?id=11939200
.PHONY: help
help:	### this screen. Keep it first target to be default
ifeq ($(UNAME), Linux)
	@grep -P '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
else
	@# this is not tested, but prepared in advance for you, Mac drivers
	@awk -F ':.*###' '$$0 ~ FS {printf "%15s%s\n", $$1 ":", $$2}' $(MAKEFILE_LIST) | grep -v '@awk' | sort
endif

.PHONY: all clean megacheck release snapshot

all: snapshot

.PHONY: build
build: ### build the binary
	@go build -ldflags "-X gitlab.com/yakshaving.art/nomad-exporter/version.Version=$(VERSION) -X gitlab.com/yakshaving.art/nomad-exporter/version.Commit=$(COMMIT_ID) -X gitlab.com/yakshaving.art/nomad-exporter/version.Date=$(COMMIT_DATE)"

.PHONY: clean
clean: ### clean the .dist folder created by goreleaser
	rm -rf ./dist

.PHONY: release
release: ### release the binary and images using goreleaser
	goreleaser --rm-dist

.PHONY: snapshot
snapshot: ### creates a snapshotted image using goreleaser
	goreleaser --snapshot --rm-dist
