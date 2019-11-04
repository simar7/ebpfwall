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

type mockSystem struct {
	loadElf func(fn string) error
	getMaps func() map[string]goebpf.Map
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
	panic("implement me")
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
		expectedError error
		expectedLogs  []string
	}{
		{
			name: "happy path",
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
		}

		assert.Equal(t, tc.expectedError, w.createBPFSystem(), tc.name)

		loggedLogs := getAllLoggedLogs(recorded.All())
		assert.Equal(t, loggedLogs, tc.expectedLogs, tc.name)
	}
}
