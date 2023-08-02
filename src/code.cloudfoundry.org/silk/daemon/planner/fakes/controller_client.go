// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"code.cloudfoundry.org/silk/controller"
)

type ControllerClient struct {
	GetActiveLeasesStub          func() ([]controller.Lease, error)
	getRoutableLeasesMutex       sync.RWMutex
	getRoutableLeasesArgsForCall []struct{}
	getRoutableLeasesReturns     struct {
		result1 []controller.Lease
		result2 error
	}
	getRoutableLeasesReturnsOnCall map[int]struct {
		result1 []controller.Lease
		result2 error
	}
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

func (fake *ControllerClient) GetActiveLeases() ([]controller.Lease, error) {
	fake.getRoutableLeasesMutex.Lock()
	ret, specificReturn := fake.getRoutableLeasesReturnsOnCall[len(fake.getRoutableLeasesArgsForCall)]
	fake.getRoutableLeasesArgsForCall = append(fake.getRoutableLeasesArgsForCall, struct{}{})
	fake.recordInvocation("GetActiveLeases", []interface{}{})
	fake.getRoutableLeasesMutex.Unlock()
	if fake.GetActiveLeasesStub != nil {
		return fake.GetActiveLeasesStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getRoutableLeasesReturns.result1, fake.getRoutableLeasesReturns.result2
}

func (fake *ControllerClient) GetActiveLeasesCallCount() int {
	fake.getRoutableLeasesMutex.RLock()
	defer fake.getRoutableLeasesMutex.RUnlock()
	return len(fake.getRoutableLeasesArgsForCall)
}

func (fake *ControllerClient) GetActiveLeasesReturns(result1 []controller.Lease, result2 error) {
	fake.GetActiveLeasesStub = nil
	fake.getRoutableLeasesReturns = struct {
		result1 []controller.Lease
		result2 error
	}{result1, result2}
}

func (fake *ControllerClient) GetActiveLeasesReturnsOnCall(i int, result1 []controller.Lease, result2 error) {
	fake.GetActiveLeasesStub = nil
	if fake.getRoutableLeasesReturnsOnCall == nil {
		fake.getRoutableLeasesReturnsOnCall = make(map[int]struct {
			result1 []controller.Lease
			result2 error
		})
	}
	fake.getRoutableLeasesReturnsOnCall[i] = struct {
		result1 []controller.Lease
		result2 error
	}{result1, result2}
}

func (fake *ControllerClient) RenewSubnetLease(arg1 controller.Lease) error {
	fake.renewSubnetLeaseMutex.Lock()
	ret, specificReturn := fake.renewSubnetLeaseReturnsOnCall[len(fake.renewSubnetLeaseArgsForCall)]
	fake.renewSubnetLeaseArgsForCall = append(fake.renewSubnetLeaseArgsForCall, struct {
		arg1 controller.Lease
	}{arg1})
	fake.recordInvocation("RenewSubnetLease", []interface{}{arg1})
	fake.renewSubnetLeaseMutex.Unlock()
	if fake.RenewSubnetLeaseStub != nil {
		return fake.RenewSubnetLeaseStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.renewSubnetLeaseReturns.result1
}

func (fake *ControllerClient) RenewSubnetLeaseCallCount() int {
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	return len(fake.renewSubnetLeaseArgsForCall)
}

func (fake *ControllerClient) RenewSubnetLeaseArgsForCall(i int) controller.Lease {
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	return fake.renewSubnetLeaseArgsForCall[i].arg1
}

func (fake *ControllerClient) RenewSubnetLeaseReturns(result1 error) {
	fake.RenewSubnetLeaseStub = nil
	fake.renewSubnetLeaseReturns = struct {
		result1 error
	}{result1}
}

func (fake *ControllerClient) RenewSubnetLeaseReturnsOnCall(i int, result1 error) {
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

func (fake *ControllerClient) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getRoutableLeasesMutex.RLock()
	defer fake.getRoutableLeasesMutex.RUnlock()
	fake.renewSubnetLeaseMutex.RLock()
	defer fake.renewSubnetLeaseMutex.RUnlock()
	return fake.invocations
}

func (fake *ControllerClient) recordInvocation(key string, args []interface{}) {
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
