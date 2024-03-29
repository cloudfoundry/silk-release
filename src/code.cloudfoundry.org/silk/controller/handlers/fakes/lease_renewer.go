// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"code.cloudfoundry.org/silk/controller"
)

type LeaseRenewer struct {
	RenewSubnetLeaseStub        func(controller.Lease) error
	renewSubnetLeaseMutex       sync.RWMutex
	renewSubnetLeaseArgsForCall []struct {
		arg1 controller.Lease
	}
	renewSubnetLeaseReturns struct {
		result1 error
	}
	renewSubnetLeaseReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *LeaseRenewer) RenewSubnetLease(arg1 controller.Lease) error {
	fake.renewSubnetLeaseMutex.Lock()
	ret, specificReturn := fake.renewSubnetLeaseReturnsOnCall[len(fake.renewSubnetLeaseArgsForCall)]
	fake.renewSubnetLeaseArgsForCall = append(fake.renewSubnetLeaseArgsForCall, struct {
		arg1 controller.Lease
	}{arg1})
	stub := fake.RenewSubnetLeaseStub
	fakeReturns := fake.renewSubnetLeaseReturns
	fake.recordInvocation("RenewSubnetLease", []interface{}{arg1})
	fake.renewSubnetLeaseMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *LeaseRenewer) RenewSubnetLeaseCallCount() int {
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	return len(fake.renewSubnetLeaseArgsForCall)
}

func (fake *LeaseRenewer) RenewSubnetLeaseCalls(stub func(controller.Lease) error) {
	fake.renewSubnetLeaseMutex.Lock()
	defer fake.renewSubnetLeaseMutex.Unlock()
	fake.RenewSubnetLeaseStub = stub
}

func (fake *LeaseRenewer) RenewSubnetLeaseArgsForCall(i int) controller.Lease {
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	argsForCall := fake.renewSubnetLeaseArgsForCall[i]
	return argsForCall.arg1
}

func (fake *LeaseRenewer) RenewSubnetLeaseReturns(result1 error) {
	fake.renewSubnetLeaseMutex.Lock()
	defer fake.renewSubnetLeaseMutex.Unlock()
	fake.RenewSubnetLeaseStub = nil
	fake.renewSubnetLeaseReturns = struct {
		result1 error
	}{result1}
}

func (fake *LeaseRenewer) RenewSubnetLeaseReturnsOnCall(i int, result1 error) {
	fake.renewSubnetLeaseMutex.Lock()
	defer fake.renewSubnetLeaseMutex.Unlock()
	fake.RenewSubnetLeaseStub = nil
	if fake.renewSubnetLeaseReturnsOnCall == nil {
		fake.renewSubnetLeaseReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.renewSubnetLeaseReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *LeaseRenewer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *LeaseRenewer) recordInvocation(key string, args []interface{}) {
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
