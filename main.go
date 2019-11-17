package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/dropbox/goebpf"
	"go.uber.org/zap"
)

type IPAddressList []string

// Implements flag.Value
func (i *IPAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

// Implements flag.Value
func (i *IPAddressList) Set(value string) error {
	if len(*i) == 16 {
		return ErrTooManyIPs
	}
	// Validate that value is correct IPv4 address
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s "+ErrInvalidIP.Error(), value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("unable to initialize logger: ", err)
	}
	defer logger.Sync()

	w := Wall{
		lg: logger.Sugar(),
		FirewallConfig: FirewallConfig{
			Iface: flag.String("iface", "", "Interface to bind XDP program to"),
			ELF:   flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file"),
		},
		bpf: goebpf.NewDefaultEbpfSystem(),
	}

	flag.Var(&w.IPAddrs, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()

	if *w.Iface == "" {
		flag.PrintDefaults()
		log.Fatal("-iface is required.")
	}

	if len(w.IPAddrs) <= 0 {
		flag.PrintDefaults()
		log.Fatal("at least one IPv4 address to DROP required to the -drop flag.")
	}

	if err := w.createBPFSystem(); err != nil {
		w.lg.Fatal("failed to load elf: ", err)
	}

	if err = w.getBPFMaps(); err != nil {
		w.lg.Fatal("failed to load bpf maps: ", err)
	}

	if err = w.getProgramByName(); err != nil {
		w.lg.Fatalf("failed to load program: ", err)
	}

	if err = w.populateBlackList(); err != nil {
		w.lg.Fatalf("failed to populate blacklist: ", err)
	}

	if err = w.loadXDP(); err != nil {
		w.lg.Fatalf("unable to load XDP program into the kernel: ", err)
	}
}
