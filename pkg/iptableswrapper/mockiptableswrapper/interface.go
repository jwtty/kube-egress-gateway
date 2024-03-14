// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/iptableswrapper/iptables.go

// Package mockiptableswrapper is a generated GoMock package.
package mockiptableswrapper

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"

	iptableswrapper "github.com/Azure/kube-egress-gateway/pkg/iptableswrapper"
)

// MockIpTables is a mock of IpTables interface.
type MockIpTables struct {
	ctrl     *gomock.Controller
	recorder *MockIpTablesMockRecorder
}

// MockIpTablesMockRecorder is the mock recorder for MockIpTables.
type MockIpTablesMockRecorder struct {
	mock *MockIpTables
}

// NewMockIpTables creates a new mock instance.
func NewMockIpTables(ctrl *gomock.Controller) *MockIpTables {
	mock := &MockIpTables{ctrl: ctrl}
	mock.recorder = &MockIpTablesMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIpTables) EXPECT() *MockIpTablesMockRecorder {
	return m.recorder
}

// AppendUnique mocks base method.
func (m *MockIpTables) AppendUnique(table, chain string, rulespec ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{table, chain}
	for _, a := range rulespec {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AppendUnique", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// AppendUnique indicates an expected call of AppendUnique.
func (mr *MockIpTablesMockRecorder) AppendUnique(table, chain interface{}, rulespec ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{table, chain}, rulespec...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppendUnique", reflect.TypeOf((*MockIpTables)(nil).AppendUnique), varargs...)
}

// Delete mocks base method.
func (m *MockIpTables) Delete(table, chain string, rulespec ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{table, chain}
	for _, a := range rulespec {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Delete", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockIpTablesMockRecorder) Delete(table, chain interface{}, rulespec ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{table, chain}, rulespec...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockIpTables)(nil).Delete), varargs...)
}

// Exists mocks base method.
func (m *MockIpTables) Exists(table, chain string, rulespec ...string) (bool, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{table, chain}
	for _, a := range rulespec {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Exists", varargs...)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Exists indicates an expected call of Exists.
func (mr *MockIpTablesMockRecorder) Exists(table, chain interface{}, rulespec ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{table, chain}, rulespec...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exists", reflect.TypeOf((*MockIpTables)(nil).Exists), varargs...)
}

// Insert mocks base method.
func (m *MockIpTables) Insert(table, chain string, pos int, rulespec ...string) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{table, chain, pos}
	for _, a := range rulespec {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Insert", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Insert indicates an expected call of Insert.
func (mr *MockIpTablesMockRecorder) Insert(table, chain, pos interface{}, rulespec ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{table, chain, pos}, rulespec...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Insert", reflect.TypeOf((*MockIpTables)(nil).Insert), varargs...)
}

// List mocks base method.
func (m *MockIpTables) List(table, chain string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", table, chain)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockIpTablesMockRecorder) List(table, chain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockIpTables)(nil).List), table, chain)
}

// MockInterface is a mock of Interface interface.
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface.
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance.
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// New mocks base method.
func (m *MockInterface) New() (iptableswrapper.IpTables, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "New")
	ret0, _ := ret[0].(iptableswrapper.IpTables)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// New indicates an expected call of New.
func (mr *MockInterfaceMockRecorder) New() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "New", reflect.TypeOf((*MockInterface)(nil).New))
}
