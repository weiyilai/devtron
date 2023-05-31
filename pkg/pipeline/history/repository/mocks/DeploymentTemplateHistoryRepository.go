// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	pg "github.com/go-pg/pg"
	mock "github.com/stretchr/testify/mock"

	repository "github.com/devtron-labs/devtron/pkg/pipeline/history/repository"
)

// DeploymentTemplateHistoryRepository is an autogenerated mock type for the DeploymentTemplateHistoryRepository type
type DeploymentTemplateHistoryRepository struct {
	mock.Mock
}

// CreateHistory provides a mock function with given fields: chart
func (_m *DeploymentTemplateHistoryRepository) CreateHistory(chart *repository.DeploymentTemplateHistory) (*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(chart)

	var r0 *repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(*repository.DeploymentTemplateHistory) *repository.DeploymentTemplateHistory); ok {
		r0 = rf(chart)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*repository.DeploymentTemplateHistory) error); ok {
		r1 = rf(chart)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateHistoryWithTxn provides a mock function with given fields: chart, tx
func (_m *DeploymentTemplateHistoryRepository) CreateHistoryWithTxn(chart *repository.DeploymentTemplateHistory, tx *pg.Tx) (*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(chart, tx)

	var r0 *repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(*repository.DeploymentTemplateHistory, *pg.Tx) *repository.DeploymentTemplateHistory); ok {
		r0 = rf(chart, tx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*repository.DeploymentTemplateHistory, *pg.Tx) error); ok {
		r1 = rf(chart, tx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeployedHistoryList provides a mock function with given fields: pipelineId, baseConfigId
func (_m *DeploymentTemplateHistoryRepository) GetDeployedHistoryList(pipelineId int, baseConfigId int) ([]*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(pipelineId, baseConfigId)

	var r0 []*repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(int, int) []*repository.DeploymentTemplateHistory); ok {
		r0 = rf(pipelineId, baseConfigId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(pipelineId, baseConfigId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeploymentDetailsForDeployedTemplateHistory provides a mock function with given fields: pipelineId, offset, limit
func (_m *DeploymentTemplateHistoryRepository) GetDeploymentDetailsForDeployedTemplateHistory(pipelineId int, offset int, limit int) ([]*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(pipelineId, offset, limit)

	var r0 []*repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(int, int, int) []*repository.DeploymentTemplateHistory); ok {
		r0 = rf(pipelineId, offset, limit)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int, int, int) error); ok {
		r1 = rf(pipelineId, offset, limit)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetHistoryByPipelineIdAndWfrId provides a mock function with given fields: pipelineId, wfrId
func (_m *DeploymentTemplateHistoryRepository) GetHistoryByPipelineIdAndWfrId(pipelineId int, wfrId int) (*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(pipelineId, wfrId)

	var r0 *repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(int, int) *repository.DeploymentTemplateHistory); ok {
		r0 = rf(pipelineId, wfrId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(pipelineId, wfrId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetHistoryForDeployedTemplateById provides a mock function with given fields: id, pipelineId
func (_m *DeploymentTemplateHistoryRepository) GetHistoryForDeployedTemplateById(id int, pipelineId int) (*repository.DeploymentTemplateHistory, error) {
	ret := _m.Called(id, pipelineId)

	var r0 *repository.DeploymentTemplateHistory
	if rf, ok := ret.Get(0).(func(int, int) *repository.DeploymentTemplateHistory); ok {
		r0 = rf(id, pipelineId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repository.DeploymentTemplateHistory)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int, int) error); ok {
		r1 = rf(id, pipelineId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewDeploymentTemplateHistoryRepository interface {
	mock.TestingT
	Cleanup(func())
}

// NewDeploymentTemplateHistoryRepository creates a new instance of DeploymentTemplateHistoryRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewDeploymentTemplateHistoryRepository(t mockConstructorTestingTNewDeploymentTemplateHistoryRepository) *DeploymentTemplateHistoryRepository {
	mock := &DeploymentTemplateHistoryRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}