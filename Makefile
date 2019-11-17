# Taken from: https://github.com/dropbox/goebpf/blob/master/examples/xdp/basic_firewall/Makefile

# Copyright (c) 2019 Dropbox, Inc.
# Full license can be found in the LICENSE file.

GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I../../..

GO_SOURCE := main.go wall.go
GO_BINARY := thewall

EBPF_SOURCE := ebpf_prog/xdp_fw.c
EBPF_BINARY := ebpf_prog/xdp_fw.elf

all: build_bpf build_go

build_bpf: $(EBPF_BINARY)

build_go: $(GO_BINARY)

clean:
	$(GOCLEAN)
	rm -f $(GO_BINARY)
	rm -f $(EBPF_BINARY)

test:
	go test -v ./...

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

$(GO_BINARY): $(GO_SOURCE)
	$(GOBUILD) -v -o $@
