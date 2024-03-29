// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"code.cloudfoundry.org/iptables-logger/merger"
	"code.cloudfoundry.org/iptables-logger/parser"
)

type LogMerger struct {
	MergeStub        func(parser.ParsedData) (merger.IPTablesLogData, error)
	mergeMutex       sync.RWMutex
	mergeArgsForCall []struct {
		arg1 parser.ParsedData
	}
	mergeReturns struct {
		result1 merger.IPTablesLogData
		result2 error
	}
	mergeReturnsOnCall map[int]struct {
		result1 merger.IPTablesLogData
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *LogMerger) Merge(arg1 parser.ParsedData) (merger.IPTablesLogData, error) {
	fake.mergeMutex.Lock()
	ret, specificReturn := fake.mergeReturnsOnCall[len(fake.mergeArgsForCall)]
	fake.mergeArgsForCall = append(fake.mergeArgsForCall, struct {
		arg1 parser.ParsedData
	}{arg1})
	stub := fake.MergeStub
	fakeReturns := fake.mergeReturns
	fake.recordInvocation("Merge", []interface{}{arg1})
	fake.mergeMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *LogMerger) MergeCallCount() int {
	fake.mergeMutex.RLock()
	defer fake.mergeMutex.RUnlock()
	return len(fake.mergeArgsForCall)
}

func (fake *LogMerger) MergeCalls(stub func(parser.ParsedData) (merger.IPTablesLogData, error)) {
	fake.mergeMutex.Lock()
	defer fake.mergeMutex.Unlock()
	fake.MergeStub = stub
}

func (fake *LogMerger) MergeArgsForCall(i int) parser.ParsedData {
	fake.mergeMutex.RLock()
	defer fake.mergeMutex.RUnlock()
	argsForCall := fake.mergeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *LogMerger) MergeReturns(result1 merger.IPTablesLogData, result2 error) {
	fake.mergeMutex.Lock()
	defer fake.mergeMutex.Unlock()
	fake.MergeStub = nil
	fake.mergeReturns = struct {
		result1 merger.IPTablesLogData
		result2 error
	}{result1, result2}
}

func (fake *LogMerger) MergeReturnsOnCall(i int, result1 merger.IPTablesLogData, result2 error) {
	fake.mergeMutex.Lock()
	defer fake.mergeMutex.Unlock()
	fake.MergeStub = nil
	if fake.mergeReturnsOnCall == nil {
		fake.mergeReturnsOnCall = make(map[int]struct {
			result1 merger.IPTablesLogData
			result2 error
		})
	}
	fake.mergeReturnsOnCall[i] = struct {
		result1 merger.IPTablesLogData
		result2 error
	}{result1, result2}
}

func (fake *LogMerger) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.mergeMutex.RLock()
	defer fake.mergeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *LogMerger) recordInvocation(key string, args []interface{}) {
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
