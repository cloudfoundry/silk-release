// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"github.com/containernetworking/plugins/pkg/ns"
)

type NamespaceAdapter struct {
	GetCurrentNSStub        func() (ns.NetNS, error)
	getCurrentNSMutex       sync.RWMutex
	getCurrentNSArgsForCall []struct {
	}
	getCurrentNSReturns struct {
		result1 ns.NetNS
		result2 error
	}
	getCurrentNSReturnsOnCall map[int]struct {
		result1 ns.NetNS
		result2 error
	}
	GetNSStub        func(string) (ns.NetNS, error)
	getNSMutex       sync.RWMutex
	getNSArgsForCall []struct {
		arg1 string
	}
	getNSReturns struct {
		result1 ns.NetNS
		result2 error
	}
	getNSReturnsOnCall map[int]struct {
		result1 ns.NetNS
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *NamespaceAdapter) GetCurrentNS() (ns.NetNS, error) {
	fake.getCurrentNSMutex.Lock()
	ret, specificReturn := fake.getCurrentNSReturnsOnCall[len(fake.getCurrentNSArgsForCall)]
	fake.getCurrentNSArgsForCall = append(fake.getCurrentNSArgsForCall, struct {
	}{})
	stub := fake.GetCurrentNSStub
	fakeReturns := fake.getCurrentNSReturns
	fake.recordInvocation("GetCurrentNS", []interface{}{})
	fake.getCurrentNSMutex.Unlock()
	if stub != nil {
		return stub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *NamespaceAdapter) GetCurrentNSCallCount() int {
	fake.getCurrentNSMutex.RLock()
	defer fake.getCurrentNSMutex.RUnlock()
	return len(fake.getCurrentNSArgsForCall)
}

func (fake *NamespaceAdapter) GetCurrentNSCalls(stub func() (ns.NetNS, error)) {
	fake.getCurrentNSMutex.Lock()
	defer fake.getCurrentNSMutex.Unlock()
	fake.GetCurrentNSStub = stub
}

func (fake *NamespaceAdapter) GetCurrentNSReturns(result1 ns.NetNS, result2 error) {
	fake.getCurrentNSMutex.Lock()
	defer fake.getCurrentNSMutex.Unlock()
	fake.GetCurrentNSStub = nil
	fake.getCurrentNSReturns = struct {
		result1 ns.NetNS
		result2 error
	}{result1, result2}
}

func (fake *NamespaceAdapter) GetCurrentNSReturnsOnCall(i int, result1 ns.NetNS, result2 error) {
	fake.getCurrentNSMutex.Lock()
	defer fake.getCurrentNSMutex.Unlock()
	fake.GetCurrentNSStub = nil
	if fake.getCurrentNSReturnsOnCall == nil {
		fake.getCurrentNSReturnsOnCall = make(map[int]struct {
			result1 ns.NetNS
			result2 error
		})
	}
	fake.getCurrentNSReturnsOnCall[i] = struct {
		result1 ns.NetNS
		result2 error
	}{result1, result2}
}

func (fake *NamespaceAdapter) GetNS(arg1 string) (ns.NetNS, error) {
	fake.getNSMutex.Lock()
	ret, specificReturn := fake.getNSReturnsOnCall[len(fake.getNSArgsForCall)]
	fake.getNSArgsForCall = append(fake.getNSArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.GetNSStub
	fakeReturns := fake.getNSReturns
	fake.recordInvocation("GetNS", []interface{}{arg1})
	fake.getNSMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *NamespaceAdapter) GetNSCallCount() int {
	fake.getNSMutex.RLock()
	defer fake.getNSMutex.RUnlock()
	return len(fake.getNSArgsForCall)
}

func (fake *NamespaceAdapter) GetNSCalls(stub func(string) (ns.NetNS, error)) {
	fake.getNSMutex.Lock()
	defer fake.getNSMutex.Unlock()
	fake.GetNSStub = stub
}

func (fake *NamespaceAdapter) GetNSArgsForCall(i int) string {
	fake.getNSMutex.RLock()
	defer fake.getNSMutex.RUnlock()
	argsForCall := fake.getNSArgsForCall[i]
	return argsForCall.arg1
}

func (fake *NamespaceAdapter) GetNSReturns(result1 ns.NetNS, result2 error) {
	fake.getNSMutex.Lock()
	defer fake.getNSMutex.Unlock()
	fake.GetNSStub = nil
	fake.getNSReturns = struct {
		result1 ns.NetNS
		result2 error
	}{result1, result2}
}

func (fake *NamespaceAdapter) GetNSReturnsOnCall(i int, result1 ns.NetNS, result2 error) {
	fake.getNSMutex.Lock()
	defer fake.getNSMutex.Unlock()
	fake.GetNSStub = nil
	if fake.getNSReturnsOnCall == nil {
		fake.getNSReturnsOnCall = make(map[int]struct {
			result1 ns.NetNS
			result2 error
		})
	}
	fake.getNSReturnsOnCall[i] = struct {
		result1 ns.NetNS
		result2 error
	}{result1, result2}
}

func (fake *NamespaceAdapter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getCurrentNSMutex.RLock()
	defer fake.getCurrentNSMutex.RUnlock()
	fake.getNSMutex.RLock()
	defer fake.getNSMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *NamespaceAdapter) recordInvocation(key string, args []interface{}) {
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
