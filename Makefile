REGISTRY              := eu.gcr.io/gardener-project
EXECUTABLE            := nwpdcli
PROJECT               := github/gardener/network-problem-detector
IMAGE_REPOSITORY      := $(REGISTRY)/test/network-problem-detector
VERSION               := $(shell cat VERSION)
IMAGE_TAG             := $(VERSION)
EFFECTIVE_VERSION     := $(VERSION)-$(shell git rev-parse HEAD)

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor
	@GO111MODULE=on go mod tidy


#.PHONY: check
#check:
#	@.ci/check

.PHONY: build
build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o $(EXECUTABLE) \
        -mod=vendor \
	    -ldflags "-X main.Version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/nwpd

.PHONY: build-local
build-local:
	@CGO_ENABLED=1 GO111MODULE=on go build -o $(EXECUTABLE) \
	    -race \
        -mod=vendor \
	    -gcflags="all=-N -l" \
	    -ldflags "-X main.Version=$(VERSION)-$(shell git rev-parse HEAD)"\
	    ./cmd/nwpd


.PHONY: release
release:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o $(EXECUTABLE) \
        -mod=vendor \
        -ldflags "-w -X main.Version=$(VERSION)" \
	    ./cmd/nwpd

#.PHONY: test
#test:
#	GO111MODULE=on go test -mod=vendor ./pkg/...
#	@echo ----- Skipping long running integration tests, use \'make alltests\' to run all tests -----
#	test/integration/run.sh $(kindargs) -- -skip Many $(args)

.PHONY: generate-proto
generate-proto:
	@protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    --experimental_allow_proto3_optional \
    pkg/common/nwpd/nwpd.proto

#.PHONY: install-requirements
#install-requirements:
#	@go install -mod=vendor github.com/onsi/ginkgo/ginkgo
#	@GO111MODULE=off go get golang.org/x/tools/cmd/goimports
#	@./hack/install-requirements.sh

.PHONY: docker-images
docker-images:
	@docker build -t $(IMAGE_REPOSITORY):$(IMAGE_TAG) -f Dockerfile .
