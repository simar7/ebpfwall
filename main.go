package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	tm "github.com/buger/goterm"
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

	if err = w.attachXDP(); err != nil {
		w.lg.Fatalf("unable to attach XDP program: ", err)
	}
	defer w.xdp.Detach()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ticker := time.NewTicker(time.Second * 1)

	for {
		select {
		case <-ticker.C:
			tm.Clear()
			tm.MoveCursor(1, 1)
			_, _ = tm.Println("Current Time:", time.Now().Format(time.RFC1123))
			table := tm.NewTable(0, 10, 5, ' ', 0)
			_, _ = fmt.Fprintf(table, "IP\tDROPs\n")

			for i := 0; i < len(w.IPAddrs); i++ {
				value, err := w.Matches.Lookup(i)
				if err != nil {
					continue
				}
				_, _ = fmt.Fprintf(table, "%s\t%d\n", w.IPAddrs[i], value)
			}
			_, _ = tm.Println(table)
			tm.Flush()
		case <-interrupt:
			w.lg.Info("Detaching and exiting..")
			return
		}
	}

}
