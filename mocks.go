package main

import "github.com/dropbox/goebpf"

type mockMap struct {
	insert func(interface{}, interface{}) error
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

func (mm mockMap) Insert(a interface{}, b interface{}) error {
	if mm.insert != nil {
		return mm.insert(a, b)
	}
	return nil
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
	load   func() error
	attach func(interface{}) error
}

func (mp mockProgram) Load() error {
	if mp.load != nil {
		return mp.load()
	}
	return nil
}

func (mp mockProgram) Pin(path string) error {
	panic("implement me")
}

func (mp mockProgram) Close() error {
	panic("implement me")
}

func (mp mockProgram) Attach(data interface{}) error {
	if mp.attach != nil {
		return mp.attach(data)
	}
	return nil
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
