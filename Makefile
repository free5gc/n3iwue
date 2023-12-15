ROOT_PATH = $(shell pwd)
BUILD_TIME = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT_HASH = $(shell git log -1 --oneline |  cut -c1-7)
COMMIT_TIME = $(shell git log --pretty="%ai" -1 | awk '{time=$$(1)"T"$$(2)"Z"; print time}')
LDFLAGS = -X github.com/free5gc/version.BUILD_TIME=$(BUILD_TIME) \
          -X github.com/free5gc/version.COMMIT_HASH=$(COMMIT_HASH) \
          -X github.com/free5gc/version.COMMIT_TIME=$(COMMIT_TIME)

n3iwue: clean
	@echo "Start building $(@F)...."
	go mod tidy
	CGO_ENABLED=0 go build -gcflags "$(GCFLAGS)" -ldflags "$(LDFLAGS)" -o $(ROOT_PATH)/$@ $(@F).go

debug: GCFLAGS += -N -l
debug: n3iwue

clean:
	rm -f n3iwue
