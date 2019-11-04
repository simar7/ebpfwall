// Inspired from: https://github.com/dropbox/goebpf/blob/master/examples/xdp/basic_firewall/main.go

package main

import (
	"errors"
	"flag"
	"fmt"
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
		return errors.New("Up to 16 IPv4 addresses supported")
	}
	// Validate that value is correct IPv4 address
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}

type FirewallConfig struct {
	IPAddrs IPAddressList
	ELF     string
	Iface   string
}

type Wall struct {
	lg *zap.SugaredLogger
	FirewallConfig
	bpf goebpf.System
}

func (w *Wall) createBPFSystem() error {
	if err := w.bpf.LoadElf(w.ELF); err != nil {
		w.lg.Error("loading of ELF program failed: ", err)
		return err
	}
	return nil
}

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	w := Wall{
		lg: logger.Sugar(),
		FirewallConfig: FirewallConfig{
			Iface: *flag.String("iface", "", "Interface to bind XDP program to"),
			ELF:   *flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file"),
		},
		bpf: goebpf.NewDefaultEbpfSystem(),
	}

	flag.Var(&w.IPAddrs, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()

	if w.Iface == "" {
		w.lg.Fatal("-iface is required.")
	}

	if len(w.IPAddrs) <= 0 {
		w.lg.Fatal("at least one IPv4 address to DROP required to the -drop flag.")
	}

	if err := w.createBPFSystem(); err != nil {
		w.lg.Fatal("failed to load elf: ", err)
	}
}
