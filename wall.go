package main

import (
	"errors"

	"github.com/dropbox/goebpf"
	"go.uber.org/zap"
)

const (
	EBPFMatchesMap   = "matches"
	EBPFBlacklistMap = "blacklist"
	XDPProgramName   = "firewall"
)

var (
	ErrMatchesMapNotFound   = errors.New("eBPF matches map not found")
	ErrBlackListMapNotFound = errors.New("eBPF blacklist map not found")
	ErrProgramNotFound      = errors.New("eBPF program not found")
	ErrTooManyIPs           = errors.New("maximum of 16 IPv4 addresses supported")
	ErrInvalidIP            = errors.New("invalid IP address")
)

type FirewallConfig struct {
	IPAddrs   IPAddressList
	ELF       *string
	Iface     *string
	BlackList goebpf.Map
	Matches   goebpf.Map
}

type Wall struct {
	lg *zap.SugaredLogger
	FirewallConfig
	bpf goebpf.System
	xdp goebpf.Program
}

func (w *Wall) createBPFSystem() error {
	if err := w.bpf.LoadElf(*w.ELF); err != nil {
		w.lg.Error("loading of ELF program failed: ", err)
		return err
	}
	return nil
}

func (w *Wall) getBPFMaps() error {
	w.Matches = w.bpf.GetMapByName(EBPFMatchesMap)
	if w.Matches == nil {
		w.lg.Errorf("%s: %s", EBPFMatchesMap, ErrMatchesMapNotFound)
		return ErrMatchesMapNotFound
	}

	w.BlackList = w.bpf.GetMapByName(EBPFBlacklistMap)
	if w.BlackList == nil {
		w.lg.Errorf("%s: %s", EBPFBlacklistMap, ErrBlackListMapNotFound)
		return ErrBlackListMapNotFound
	}

	return nil
}

func (w *Wall) getProgramByName() error {
	w.xdp = w.bpf.GetProgramByName("firewall")
	if w.xdp == nil {
		w.lg.Errorf("%s: %s", ErrProgramNotFound, XDPProgramName)
		return ErrProgramNotFound
	}
	return nil
}

func (w *Wall) populateBlackList() error {
	w.lg.Info("Populating blacklist with input IPs...")
	for index, ip := range w.FirewallConfig.IPAddrs {
		w.lg.Infof("%s", ip)
		if err := w.BlackList.Insert(goebpf.CreateLPMtrieKey(ip), index); err != nil {
			w.lg.Error("error adding ip: ", ip)
			return err
		}
	}
	return nil
}

func (w *Wall) loadXDP() error {
	w.lg.Info("loading XDP program into the kernel...")
	if err := w.xdp.Load(); err != nil {
		w.lg.Error("load failed, err: ", err)
		return err
	}
	return nil
}

func (w *Wall) attachXDP() error {
	w.lg.Infof("attaching XDP program to interface: %s...", *w.FirewallConfig.Iface)
	if err := w.xdp.Attach(*w.FirewallConfig.Iface); err != nil {
		w.lg.Error("attach failed, err: ", err)
		return err
	}
	return nil
}
