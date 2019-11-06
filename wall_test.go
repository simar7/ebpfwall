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

func (mm mockMap) Create() error {
	panic("implement me")
}

func (mm mockMap) GetFd() int {
	panic("implement me")
}

func (mm mockMap) GetName() string {
	panic("implement me")
}

func (mm mockMap) Close() error {
	panic("implement me")
}

func (mm mockMap) CloneTemplate() goebpf.Map {
	panic("implement me")
}

func (mm mockMap) Lookup(interface{}) ([]byte, error) {
	panic("implement me")
}

func (mm mockMap) LookupInt(interface{}) (int, error) {
	panic("implement me")
}

func (mm mockMap) LookupUint64(interface{}) (uint64, error) {
	panic("implement me")
}

func (mm mockMap) LookupString(interface{}) (string, error) {
	panic("implement me")
}

func (mm mockMap) Insert(interface{}, interface{}) error {
	panic("implement me")
}

func (mm mockMap) Update(interface{}, interface{}) error {
	panic("implement me")
}

func (mm mockMap) Upsert(interface{}, interface{}) error {
	panic("implement me")
}

func (mm mockMap) Delete(interface{}) error {
	panic("implement me")
}

type mockProgram struct {
}

func (mp mockProgram) Load() error {
	panic("implement me")
}

func (mp mockProgram) Pin(path string) error {
	panic("implement me")
}

func (mp mockProgram) Close() error {
	panic("implement me")
}

func (mp mockProgram) Attach(data interface{}) error {
	panic("implement me")
}

func (mp mockProgram) Detach() error {
	panic("implement me")
}

func (mp mockProgram) GetName() string {
	panic("implement me")
}

func (mp mockProgram) GetFd() int {
	panic("implement me")
}

func (mp mockProgram) GetSize() int {
	panic("implement me")
}

func (mp mockProgram) GetLicense() string {
	panic("implement me")
}

func (mp mockProgram) GetType() goebpf.ProgramType {
	panic("implement me")
}

type mockSystem struct {
	loadElf          func(fn string) error
	getMaps          func() map[string]goebpf.Map
	getMapByName     func(string) goebpf.Map
	getProgramByName func(string) goebpf.Program
}

func (ms mockSystem) LoadElf(fn string) error {
	if ms.loadElf != nil {
		return ms.loadElf(fn)
	}
	return nil
}

func (ms mockSystem) GetMaps() map[string]goebpf.Map {
	if ms.getMaps != nil {
		return ms.getMaps()
	}
	return map[string]goebpf.Map{}
}

func (ms mockSystem) GetMapByName(name string) goebpf.Map {
	if ms.getMapByName != nil {
		return ms.getMapByName(name)
	}
	return mockMap{}
}

func (ms mockSystem) GetPrograms() map[string]goebpf.Program {
	panic("implement me")
}

func (ms mockSystem) GetProgramByName(name string) goebpf.Program {
	if ms.getProgramByName != nil {
		return ms.getProgramByName(name)
	}
	return mockProgram{}
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
