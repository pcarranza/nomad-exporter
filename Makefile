src = $(wildcard *.go)

.PHONY: all clean megacheck release snapshot

all: snapshot

clean:
	rm -rf ./dist

release:
	goreleaser --rm-dist

snapshot:
	goreleaser --snapshot --rm-dist
