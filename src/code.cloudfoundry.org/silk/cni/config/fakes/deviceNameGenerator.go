// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"net"
	"sync"
)

type DeviceNameGenerator struct {
	GenerateForHostStub        func(net.IP) (string, error)
	generateForHostMutex       sync.RWMutex
	generateForHostArgsForCall []struct {
		arg1 net.IP
	}
	generateForHostReturns struct {
		result1 string
		result2 error
	}
	generateForHostReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	GenerateTemporaryForContainerStub        func(net.IP) (string, error)
	generateTemporaryForContainerMutex       sync.RWMutex
	generateTemporaryForContainerArgsForCall []struct {
		arg1 net.IP
	}
	generateTemporaryForContainerReturns struct {
		result1 string
		result2 error
	}
	generateTemporaryForContainerReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *DeviceNameGenerator) GenerateForHost(arg1 net.IP) (string, error) {
	fake.generateForHostMutex.Lock()
	ret, specificReturn := fake.generateForHostReturnsOnCall[len(fake.generateForHostArgsForCall)]
	fake.generateForHostArgsForCall = append(fake.generateForHostArgsForCall, struct {
		arg1 net.IP
	}{arg1})
	stub := fake.GenerateForHostStub
	fakeReturns := fake.generateForHostReturns
	fake.recordInvocation("GenerateForHost", []interface{}{arg1})
	fake.generateForHostMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *DeviceNameGenerator) GenerateForHostCallCount() int {
	fake.generateForHostMutex.RLock()
	defer fake.generateForHostMutex.RUnlock()
	return len(fake.generateForHostArgsForCall)
}

func (fake *DeviceNameGenerator) GenerateForHostCalls(stub func(net.IP) (string, error)) {
	fake.generateForHostMutex.Lock()
	defer fake.generateForHostMutex.Unlock()
	fake.GenerateForHostStub = stub
}

func (fake *DeviceNameGenerator) GenerateForHostArgsForCall(i int) net.IP {
	fake.generateForHostMutex.RLock()
	defer fake.generateForHostMutex.RUnlock()
	argsForCall := fake.generateForHostArgsForCall[i]
	return argsForCall.arg1
}

func (fake *DeviceNameGenerator) GenerateForHostReturns(result1 string, result2 error) {
	fake.generateForHostMutex.Lock()
	defer fake.generateForHostMutex.Unlock()
	fake.GenerateForHostStub = nil
	fake.generateForHostReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DeviceNameGenerator) GenerateForHostReturnsOnCall(i int, result1 string, result2 error) {
	fake.generateForHostMutex.Lock()
	defer fake.generateForHostMutex.Unlock()
	fake.GenerateForHostStub = nil
	if fake.generateForHostReturnsOnCall == nil {
		fake.generateForHostReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.generateForHostReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainer(arg1 net.IP) (string, error) {
	fake.generateTemporaryForContainerMutex.Lock()
	ret, specificReturn := fake.generateTemporaryForContainerReturnsOnCall[len(fake.generateTemporaryForContainerArgsForCall)]
	fake.generateTemporaryForContainerArgsForCall = append(fake.generateTemporaryForContainerArgsForCall, struct {
		arg1 net.IP
	}{arg1})
	stub := fake.GenerateTemporaryForContainerStub
	fakeReturns := fake.generateTemporaryForContainerReturns
	fake.recordInvocation("GenerateTemporaryForContainer", []interface{}{arg1})
	fake.generateTemporaryForContainerMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainerCallCount() int {
	fake.generateTemporaryForContainerMutex.RLock()
	defer fake.generateTemporaryForContainerMutex.RUnlock()
	return len(fake.generateTemporaryForContainerArgsForCall)
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainerCalls(stub func(net.IP) (string, error)) {
	fake.generateTemporaryForContainerMutex.Lock()
	defer fake.generateTemporaryForContainerMutex.Unlock()
	fake.GenerateTemporaryForContainerStub = stub
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainerArgsForCall(i int) net.IP {
	fake.generateTemporaryForContainerMutex.RLock()
	defer fake.generateTemporaryForContainerMutex.RUnlock()
	argsForCall := fake.generateTemporaryForContainerArgsForCall[i]
	return argsForCall.arg1
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainerReturns(result1 string, result2 error) {
	fake.generateTemporaryForContainerMutex.Lock()
	defer fake.generateTemporaryForContainerMutex.Unlock()
	fake.GenerateTemporaryForContainerStub = nil
	fake.generateTemporaryForContainerReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DeviceNameGenerator) GenerateTemporaryForContainerReturnsOnCall(i int, result1 string, result2 error) {
	fake.generateTemporaryForContainerMutex.Lock()
	defer fake.generateTemporaryForContainerMutex.Unlock()
	fake.GenerateTemporaryForContainerStub = nil
	if fake.generateTemporaryForContainerReturnsOnCall == nil {
		fake.generateTemporaryForContainerReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.generateTemporaryForContainerReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *DeviceNameGenerator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.generateForHostMutex.RLock()
	defer fake.generateForHostMutex.RUnlock()
	fake.generateTemporaryForContainerMutex.RLock()
	defer fake.generateTemporaryForContainerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *DeviceNameGenerator) recordInvocation(key string, args []interface{}) {
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
