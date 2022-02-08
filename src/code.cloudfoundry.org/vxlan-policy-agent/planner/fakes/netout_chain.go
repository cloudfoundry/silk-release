// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"code.cloudfoundry.org/cni-wrapper-plugin/netrules"
	"code.cloudfoundry.org/lib/rules"
)

type NetOutChain struct {
	DefaultRulesStub        func(string) []rules.IPTablesRule
	defaultRulesMutex       sync.RWMutex
	defaultRulesArgsForCall []struct {
		arg1 string
	}
	defaultRulesReturns struct {
		result1 []rules.IPTablesRule
	}
	defaultRulesReturnsOnCall map[int]struct {
		result1 []rules.IPTablesRule
	}
	IPTablesRulesStub        func(string, []netrules.Rule) ([]rules.IPTablesRule, error)
	iPTablesRulesMutex       sync.RWMutex
	iPTablesRulesArgsForCall []struct {
		arg1 string
		arg2 []netrules.Rule
	}
	iPTablesRulesReturns struct {
		result1 []rules.IPTablesRule
		result2 error
	}
	iPTablesRulesReturnsOnCall map[int]struct {
		result1 []rules.IPTablesRule
		result2 error
	}
	NameStub        func(string) string
	nameMutex       sync.RWMutex
	nameArgsForCall []struct {
		arg1 string
	}
	nameReturns struct {
		result1 string
	}
	nameReturnsOnCall map[int]struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *NetOutChain) DefaultRules(arg1 string) []rules.IPTablesRule {
	fake.defaultRulesMutex.Lock()
	ret, specificReturn := fake.defaultRulesReturnsOnCall[len(fake.defaultRulesArgsForCall)]
	fake.defaultRulesArgsForCall = append(fake.defaultRulesArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.DefaultRulesStub
	fakeReturns := fake.defaultRulesReturns
	fake.recordInvocation("DefaultRules", []interface{}{arg1})
	fake.defaultRulesMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *NetOutChain) DefaultRulesCallCount() int {
	fake.defaultRulesMutex.RLock()
	defer fake.defaultRulesMutex.RUnlock()
	return len(fake.defaultRulesArgsForCall)
}

func (fake *NetOutChain) DefaultRulesCalls(stub func(string) []rules.IPTablesRule) {
	fake.defaultRulesMutex.Lock()
	defer fake.defaultRulesMutex.Unlock()
	fake.DefaultRulesStub = stub
}

func (fake *NetOutChain) DefaultRulesArgsForCall(i int) string {
	fake.defaultRulesMutex.RLock()
	defer fake.defaultRulesMutex.RUnlock()
	argsForCall := fake.defaultRulesArgsForCall[i]
	return argsForCall.arg1
}

func (fake *NetOutChain) DefaultRulesReturns(result1 []rules.IPTablesRule) {
	fake.defaultRulesMutex.Lock()
	defer fake.defaultRulesMutex.Unlock()
	fake.DefaultRulesStub = nil
	fake.defaultRulesReturns = struct {
		result1 []rules.IPTablesRule
	}{result1}
}

func (fake *NetOutChain) DefaultRulesReturnsOnCall(i int, result1 []rules.IPTablesRule) {
	fake.defaultRulesMutex.Lock()
	defer fake.defaultRulesMutex.Unlock()
	fake.DefaultRulesStub = nil
	if fake.defaultRulesReturnsOnCall == nil {
		fake.defaultRulesReturnsOnCall = make(map[int]struct {
			result1 []rules.IPTablesRule
		})
	}
	fake.defaultRulesReturnsOnCall[i] = struct {
		result1 []rules.IPTablesRule
	}{result1}
}

func (fake *NetOutChain) IPTablesRules(arg1 string, arg2 []netrules.Rule) ([]rules.IPTablesRule, error) {
	var arg2Copy []netrules.Rule
	if arg2 != nil {
		arg2Copy = make([]netrules.Rule, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.iPTablesRulesMutex.Lock()
	ret, specificReturn := fake.iPTablesRulesReturnsOnCall[len(fake.iPTablesRulesArgsForCall)]
	fake.iPTablesRulesArgsForCall = append(fake.iPTablesRulesArgsForCall, struct {
		arg1 string
		arg2 []netrules.Rule
	}{arg1, arg2Copy})
	stub := fake.IPTablesRulesStub
	fakeReturns := fake.iPTablesRulesReturns
	fake.recordInvocation("IPTablesRules", []interface{}{arg1, arg2Copy})
	fake.iPTablesRulesMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *NetOutChain) IPTablesRulesCallCount() int {
	fake.iPTablesRulesMutex.RLock()
	defer fake.iPTablesRulesMutex.RUnlock()
	return len(fake.iPTablesRulesArgsForCall)
}

func (fake *NetOutChain) IPTablesRulesCalls(stub func(string, []netrules.Rule) ([]rules.IPTablesRule, error)) {
	fake.iPTablesRulesMutex.Lock()
	defer fake.iPTablesRulesMutex.Unlock()
	fake.IPTablesRulesStub = stub
}

func (fake *NetOutChain) IPTablesRulesArgsForCall(i int) (string, []netrules.Rule) {
	fake.iPTablesRulesMutex.RLock()
	defer fake.iPTablesRulesMutex.RUnlock()
	argsForCall := fake.iPTablesRulesArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *NetOutChain) IPTablesRulesReturns(result1 []rules.IPTablesRule, result2 error) {
	fake.iPTablesRulesMutex.Lock()
	defer fake.iPTablesRulesMutex.Unlock()
	fake.IPTablesRulesStub = nil
	fake.iPTablesRulesReturns = struct {
		result1 []rules.IPTablesRule
		result2 error
	}{result1, result2}
}

func (fake *NetOutChain) IPTablesRulesReturnsOnCall(i int, result1 []rules.IPTablesRule, result2 error) {
	fake.iPTablesRulesMutex.Lock()
	defer fake.iPTablesRulesMutex.Unlock()
	fake.IPTablesRulesStub = nil
	if fake.iPTablesRulesReturnsOnCall == nil {
		fake.iPTablesRulesReturnsOnCall = make(map[int]struct {
			result1 []rules.IPTablesRule
			result2 error
		})
	}
	fake.iPTablesRulesReturnsOnCall[i] = struct {
		result1 []rules.IPTablesRule
		result2 error
	}{result1, result2}
}

func (fake *NetOutChain) Name(arg1 string) string {
	fake.nameMutex.Lock()
	ret, specificReturn := fake.nameReturnsOnCall[len(fake.nameArgsForCall)]
	fake.nameArgsForCall = append(fake.nameArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.NameStub
	fakeReturns := fake.nameReturns
	fake.recordInvocation("Name", []interface{}{arg1})
	fake.nameMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *NetOutChain) NameCallCount() int {
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	return len(fake.nameArgsForCall)
}

func (fake *NetOutChain) NameCalls(stub func(string) string) {
	fake.nameMutex.Lock()
	defer fake.nameMutex.Unlock()
	fake.NameStub = stub
}

func (fake *NetOutChain) NameArgsForCall(i int) string {
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	argsForCall := fake.nameArgsForCall[i]
	return argsForCall.arg1
}

func (fake *NetOutChain) NameReturns(result1 string) {
	fake.nameMutex.Lock()
	defer fake.nameMutex.Unlock()
	fake.NameStub = nil
	fake.nameReturns = struct {
		result1 string
	}{result1}
}

func (fake *NetOutChain) NameReturnsOnCall(i int, result1 string) {
	fake.nameMutex.Lock()
	defer fake.nameMutex.Unlock()
	fake.NameStub = nil
	if fake.nameReturnsOnCall == nil {
		fake.nameReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.nameReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *NetOutChain) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.defaultRulesMutex.RLock()
	defer fake.defaultRulesMutex.RUnlock()
	fake.iPTablesRulesMutex.RLock()
	defer fake.iPTablesRulesMutex.RUnlock()
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *NetOutChain) recordInvocation(key string, args []interface{}) {
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
