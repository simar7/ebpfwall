package main

import (
	"errors"
	"net"
	"testing"

	"github.com/dropbox/goebpf"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/stretchr/testify/assert"
)

func getAllLoggedLogs(logs []observer.LoggedEntry) []string {
	var allLogs []string
	for _, log := range logs {
		allLogs = append(allLogs, log.Message)
	}
	return allLogs
}

func TestWall_createBPFSystem(t *testing.T) {
	testCases := []struct {
		name          string
		loadElfFn     func(string) error
		ElfFile       string
		expectedError error
		expectedLogs  []string
	}{
		{
			name:    "happy path",
			ElfFile: "ebpf_prog/xdp_fw.elf",
		},
		{
			name: "sad path: LoadElf() fails because of invalid file",
			loadElfFn: func(s string) error {
				return errors.New("no such file found")
			},
			expectedError: errors.New("no such file found"),
			expectedLogs:  []string{"loading of ELF program failed: no such file found"},
		},
	}

	for _, tc := range testCases {
		core, recorded := observer.New(zapcore.DebugLevel)
		zl := zap.New(core)

		w := Wall{
			lg: zl.Sugar(),
			bpf: mockSystem{
				loadElf: tc.loadElfFn,
			},
			FirewallConfig: FirewallConfig{
				IPAddrs: nil,
				ELF:     &tc.ElfFile,
				Iface:   nil,
			},
		}

		assert.Equal(t, tc.expectedError, w.createBPFSystem(), tc.name)

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, tc.expectedLogs, loggedLogs, tc.name)
	}
}

func TestWall_getBPFMaps(t *testing.T) {
	testCases := []struct {
		name             string
		getMapByNameFunc func(string) goebpf.Map
		expectedError    error
		expectedLogs     []string
	}{
		{
			name: "happy path",
		},
		{
			name: "sad path: matches map retrieval fails",
			getMapByNameFunc: func(mapQueryString string) goebpf.Map {
				switch mapQueryString {
				case EBPFMatchesMap:
					return nil
				default:
					assert.Failf(t, "unexpected map access: %s", mapQueryString)
				}
				return nil
			},
			expectedError: ErrMatchesMapNotFound,
			expectedLogs:  []string{"matches: eBPF matches map not found"},
		},
		{
			name: "sad path: blacklist map retrieval fails",
			getMapByNameFunc: func(mapQueryString string) goebpf.Map {
				switch mapQueryString {
				case EBPFMatchesMap:
					return mockMap{}
				case EBPFBlacklistMap:
					return nil
				default:
					assert.Failf(t, "unexpected map access: %s", mapQueryString)
				}
				return nil
			},
			expectedError: ErrBlackListMapNotFound,
			expectedLogs:  []string{"blacklist: eBPF blacklist map not found"},
		},
	}

	for _, tc := range testCases {
		core, recorded := observer.New(zapcore.DebugLevel)
		zl := zap.New(core)

		w := Wall{
			lg: zl.Sugar(),
			bpf: mockSystem{
				getMapByName: tc.getMapByNameFunc,
			},
		}

		err := w.getBPFMaps()
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError, err, tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, tc.expectedLogs, loggedLogs, tc.name)
	}
}

func TestWall_getProgramByName(t *testing.T) {
	testCases := []struct {
		name                 string
		getProgramByNameFunc func(string) goebpf.Program
		expectedError        error
		expectedLogs         []string
	}{
		{
			name: "happy path",
		},
		{
			name: "sad path: failed to retrieve firewall xdp program",
			getProgramByNameFunc: func(programName string) goebpf.Program {
				switch programName {
				case "firewall":
					return nil
				default:
					assert.Failf(t, "unexpected program name: %s", programName)
				}
				return nil
			},
			expectedError: ErrProgramNotFound,
			expectedLogs:  []string{"eBPF program not found: firewall"},
		},
	}

	for _, tc := range testCases {
		core, recorded := observer.New(zapcore.DebugLevel)
		zl := zap.New(core)

		w := Wall{
			lg: zl.Sugar(),
			bpf: mockSystem{
				getProgramByName: tc.getProgramByNameFunc,
			},
		}

		err := w.getProgramByName()
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError, err, tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, tc.expectedLogs, loggedLogs, tc.name)
	}
}

func TestWall_populateBlackList(t *testing.T) {
	testCases := []struct {
		name                string
		blackListInsertFunc func(interface{}, interface{}) error
		expectedLogs        []string
		expectedError       error
	}{
		{
			name: "happy path with two IP addresses in blacklist",
			blackListInsertFunc: func(ip interface{}, index interface{}) error {
				switch index {
				case 0:
					assert.Equal(t, &net.IPNet{
						IP:   net.IP{0x1, 0x2, 0x3, 0x4},
						Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
					}, ip)
				case 1:
					assert.Equal(t, &net.IPNet{
						IP:   net.IP{0x5, 0x6, 0x7, 0x0}, // 5.6.7.8/24 is added as 5.6.7.0/24 for the range
						Mask: net.IPMask{0xff, 0xff, 0xff, 0x0},
					}, ip)
				default:
					assert.FailNow(t, "unexpected index ip combination found: ", ip, index)
				}
				return nil
			},
			expectedLogs: []string{"Populating blacklist with input IPs...", "1.2.3.4/32", "5.6.7.8/24"},
		},
		{
			name: "sad path error adding ip address into LPMtrie",
			blackListInsertFunc: func(i interface{}, i2 interface{}) error {
				return errors.New("error adding ip")
			},
			expectedError: errors.New("error adding ip"),
			expectedLogs:  []string{"Populating blacklist with input IPs...", "1.2.3.4/32", "error adding ip: 1.2.3.4/32"},
		},
	}

	for _, tc := range testCases {
		core, recorded := observer.New(zapcore.DebugLevel)
		zl := zap.New(core)

		w := Wall{
			lg: zl.Sugar(),
			FirewallConfig: FirewallConfig{
				IPAddrs: IPAddressList{
					"1.2.3.4/32",
					"5.6.7.8/24",
				},
				BlackList: mockMap{
					insert: tc.blackListInsertFunc,
				},
			},
		}
		assert.Equal(t, tc.expectedError, w.populateBlackList(), tc.name)

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, tc.expectedLogs, loggedLogs, tc.name)
	}

}

func TestWall_loadXDP(t *testing.T) {
	testCases := []struct {
		name          string
		loadFunc      func() error
		expectedError error
		expectedLogs  []string
	}{
		{
			name:         "happy path",
			expectedLogs: []string{"loading XDP program into the kernel..."},
		},
		{
			name: "sad path: load func returns an error",
			loadFunc: func() error {
				return errors.New("loading of program failed")
			},
			expectedLogs: []string{
				"loading XDP program into the kernel...",
				"load failed, err: loading of program failed",
			},
			expectedError: errors.New("loading of program failed"),
		},
	}

	for _, tc := range testCases {
		core, recorded := observer.New(zapcore.DebugLevel)
		zl := zap.New(core)

		w := Wall{
			lg: zl.Sugar(),
			xdp: mockProgram{
				load: tc.loadFunc,
			},
		}
		assert.Equal(t, tc.expectedError, w.loadXDP(), tc.name)

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, tc.expectedLogs, loggedLogs, tc.name)
	}
}
