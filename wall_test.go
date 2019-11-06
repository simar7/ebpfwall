package main

import (
	"errors"
	"testing"

	"github.com/dropbox/goebpf"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/stretchr/testify/assert"
)

type mockMap struct {
}

func (m mockMap) Create() error {
	panic("implement me")
}

func (m mockMap) GetFd() int {
	panic("implement me")
}

func (m mockMap) GetName() string {
	panic("implement me")
}

func (m mockMap) Close() error {
	panic("implement me")
}

func (m mockMap) CloneTemplate() goebpf.Map {
	panic("implement me")
}

func (m mockMap) Lookup(interface{}) ([]byte, error) {
	panic("implement me")
}

func (m mockMap) LookupInt(interface{}) (int, error) {
	panic("implement me")
}

func (m mockMap) LookupUint64(interface{}) (uint64, error) {
	panic("implement me")
}

func (m mockMap) LookupString(interface{}) (string, error) {
	panic("implement me")
}

func (m mockMap) Insert(interface{}, interface{}) error {
	panic("implement me")
}

func (m mockMap) Update(interface{}, interface{}) error {
	panic("implement me")
}

func (m mockMap) Upsert(interface{}, interface{}) error {
	panic("implement me")
}

func (m mockMap) Delete(interface{}) error {
	panic("implement me")
}

type mockSystem struct {
	loadElf      func(fn string) error
	getMaps      func() map[string]goebpf.Map
	getMapByName func(string) goebpf.Map
}

func (m mockSystem) LoadElf(fn string) error {
	if m.loadElf != nil {
		return m.loadElf(fn)
	}
	return nil
}

func (m mockSystem) GetMaps() map[string]goebpf.Map {
	if m.getMaps != nil {
		return m.getMaps()
	}
	return map[string]goebpf.Map{}
}

func (m mockSystem) GetMapByName(name string) goebpf.Map {
	if m.getMapByName != nil {
		return m.getMapByName(name)
	}
	return mockMap{}
}

func (m mockSystem) GetPrograms() map[string]goebpf.Program {
	panic("implement me")
}

func (m mockSystem) GetProgramByName(name string) goebpf.Program {
	panic("implement me")
}

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
			expectedError: errors.New("eBPF matches map not found"),
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
			expectedError: errors.New("eBPF blacklist map not found"),
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
