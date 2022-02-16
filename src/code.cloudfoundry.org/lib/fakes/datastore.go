// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"code.cloudfoundry.org/lib/datastore"
)

type Datastore struct {
	AddStub        func(string, string, map[string]interface{}) error
	addMutex       sync.RWMutex
	addArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 map[string]interface{}
	}
	addReturns struct {
		result1 error
	}
	addReturnsOnCall map[int]struct {
		result1 error
	}
	DeleteStub        func(string) (datastore.Container, error)
	deleteMutex       sync.RWMutex
	deleteArgsForCall []struct {
		arg1 string
	}
	deleteReturns struct {
		result1 datastore.Container
		result2 error
	}
	deleteReturnsOnCall map[int]struct {
		result1 datastore.Container
		result2 error
	}
	ReadAllStub        func() (map[string]datastore.Container, error)
	readAllMutex       sync.RWMutex
	readAllArgsForCall []struct {
	}
	readAllReturns struct {
		result1 map[string]datastore.Container
		result2 error
	}
	readAllReturnsOnCall map[int]struct {
		result1 map[string]datastore.Container
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Datastore) Add(arg1 string, arg2 string, arg3 map[string]interface{}) error {
	fake.addMutex.Lock()
	ret, specificReturn := fake.addReturnsOnCall[len(fake.addArgsForCall)]
	fake.addArgsForCall = append(fake.addArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 map[string]interface{}
	}{arg1, arg2, arg3})
	stub := fake.AddStub
	fakeReturns := fake.addReturns
	fake.recordInvocation("Add", []interface{}{arg1, arg2, arg3})
	fake.addMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *Datastore) AddCallCount() int {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	return len(fake.addArgsForCall)
}

func (fake *Datastore) AddCalls(stub func(string, string, map[string]interface{}) error) {
	fake.addMutex.Lock()
	defer fake.addMutex.Unlock()
	fake.AddStub = stub
}

func (fake *Datastore) AddArgsForCall(i int) (string, string, map[string]interface{}) {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	argsForCall := fake.addArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *Datastore) AddReturns(result1 error) {
	fake.addMutex.Lock()
	defer fake.addMutex.Unlock()
	fake.AddStub = nil
	fake.addReturns = struct {
		result1 error
	}{result1}
}

func (fake *Datastore) AddReturnsOnCall(i int, result1 error) {
	fake.addMutex.Lock()
	defer fake.addMutex.Unlock()
	fake.AddStub = nil
	if fake.addReturnsOnCall == nil {
		fake.addReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.addReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Datastore) Delete(arg1 string) (datastore.Container, error) {
	fake.deleteMutex.Lock()
	ret, specificReturn := fake.deleteReturnsOnCall[len(fake.deleteArgsForCall)]
	fake.deleteArgsForCall = append(fake.deleteArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.DeleteStub
	fakeReturns := fake.deleteReturns
	fake.recordInvocation("Delete", []interface{}{arg1})
	fake.deleteMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Datastore) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *Datastore) DeleteCalls(stub func(string) (datastore.Container, error)) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = stub
}

func (fake *Datastore) DeleteArgsForCall(i int) string {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	argsForCall := fake.deleteArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Datastore) DeleteReturns(result1 datastore.Container, result2 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 datastore.Container
		result2 error
	}{result1, result2}
}

func (fake *Datastore) DeleteReturnsOnCall(i int, result1 datastore.Container, result2 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = nil
	if fake.deleteReturnsOnCall == nil {
		fake.deleteReturnsOnCall = make(map[int]struct {
			result1 datastore.Container
			result2 error
		})
	}
	fake.deleteReturnsOnCall[i] = struct {
		result1 datastore.Container
		result2 error
	}{result1, result2}
}

func (fake *Datastore) ReadAll() (map[string]datastore.Container, error) {
	fake.readAllMutex.Lock()
	ret, specificReturn := fake.readAllReturnsOnCall[len(fake.readAllArgsForCall)]
	fake.readAllArgsForCall = append(fake.readAllArgsForCall, struct {
	}{})
	stub := fake.ReadAllStub
	fakeReturns := fake.readAllReturns
	fake.recordInvocation("ReadAll", []interface{}{})
	fake.readAllMutex.Unlock()
	if stub != nil {
		return stub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *Datastore) ReadAllCallCount() int {
	fake.readAllMutex.RLock()
	defer fake.readAllMutex.RUnlock()
	return len(fake.readAllArgsForCall)
}

func (fake *Datastore) ReadAllCalls(stub func() (map[string]datastore.Container, error)) {
	fake.readAllMutex.Lock()
	defer fake.readAllMutex.Unlock()
	fake.ReadAllStub = stub
}

func (fake *Datastore) ReadAllReturns(result1 map[string]datastore.Container, result2 error) {
	fake.readAllMutex.Lock()
	defer fake.readAllMutex.Unlock()
	fake.ReadAllStub = nil
	fake.readAllReturns = struct {
		result1 map[string]datastore.Container
		result2 error
	}{result1, result2}
}

func (fake *Datastore) ReadAllReturnsOnCall(i int, result1 map[string]datastore.Container, result2 error) {
	fake.readAllMutex.Lock()
	defer fake.readAllMutex.Unlock()
	fake.ReadAllStub = nil
	if fake.readAllReturnsOnCall == nil {
		fake.readAllReturnsOnCall = make(map[int]struct {
			result1 map[string]datastore.Container
			result2 error
		})
	}
	fake.readAllReturnsOnCall[i] = struct {
		result1 map[string]datastore.Container
		result2 error
	}{result1, result2}
}

func (fake *Datastore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	fake.readAllMutex.RLock()
	defer fake.readAllMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Datastore) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ datastore.Datastore = new(Datastore)
