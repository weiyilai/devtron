/*
 * Copyright (c) 2020-2024. Devtron Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package repository

import (
	"github.com/devtron-labs/devtron/internal/sql/repository/helper"
	securityBean "github.com/devtron-labs/devtron/pkg/policyGovernance/security/imageScanning/repository/bean"
	"github.com/devtron-labs/devtron/pkg/sql"
	"github.com/devtron-labs/devtron/util"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
)

type CveStore struct {
	tableName struct{} `sql:"cve_store" pg:",discard_unknown_columns"`
	Name      string   `sql:"name,pk"`

	// Deprecated: Severity, use StandardSeverity for all read purposes
	Severity securityBean.Severity `sql:"severity,notnull"`
	// Deprecated: Package
	Package string `sql:"package,notnull"` // deprecated, storing package data in image_scan_execution_result table
	// Deprecated: Version
	Version string `sql:"version,notnull"`
	// Deprecated: FixedVersion
	FixedVersion string `sql:"fixed_version,notnull"`

	// StandardSeverity is the actual severity. use GetSeverity method to get severity of the vulnerability
	// earlier severity is maintained in Severity column by merging HIGH and CRITICAL severities.
	// later we introduced new column StandardSeverity to store raw severity, but didn't migrate the existing Severity data to StandardSeverity.
	// currently, we deprecated Severity.
	StandardSeverity *securityBean.Severity `sql:"standard_severity"`
	sql.AuditLog
}

// GetSeverity returns the actual severity of the vulnerability.
func (cve *CveStore) GetSeverity() securityBean.Severity {
	if cve.StandardSeverity == nil {
		// we need this as there was a time when StandardSeverity didn't exist.
		// and migration of Severity data to StandardSeverity is not done.
		return cve.Severity
	}
	return *cve.StandardSeverity
}

func (cve *CveStore) SetStandardSeverity(severity securityBean.Severity) {
	cve.Severity = severity
	cve.StandardSeverity = &severity
}

type VulnerabilityRequest struct {
	AppName    string `json:"appName"`
	CveName    string `json:"cveName"`
	EnvIds     []int  `json:"envIds"`
	ClusterIds []int  `json:"clusterIds"`
	Offset     int    `json:"offset"`
	Size       int    `json:"size"`
}

type VulnerabilityExposure struct {
	AppName string `json:"appName"`
	EnvName string `json:"envName"`
	AppId   int    `json:"appId"`
	EnvId   int    `json:"envId"`
	//ClusterId     int    `json:"clusterId"`
	AppType       helper.AppType `json:"appType"`
	Blocked       bool           `json:"blocked"`
	PipelineEnvId int            `json:"-"`
	ChartEnvId    int            `json:"-"`
}

type VulnerabilityExposureListingResponse struct {
	Offset                int                      `json:"offset"`
	Size                  int                      `json:"size"`
	Total                 int                      `json:"total"`
	VulnerabilityExposure []*VulnerabilityExposure `json:"list"`
}

type CveStoreRepository interface {
	Save(model *CveStore) error
	FindAll() ([]*CveStore, error)
	FindByCveNames(names []string) ([]*CveStore, error)
	FindByName(name string) (*CveStore, error)
	Update(model *CveStore) error
	VulnerabilityExposure(request *VulnerabilityRequest) ([]*VulnerabilityExposure, error)
}

type CveStoreRepositoryImpl struct {
	dbConnection *pg.DB
	logger       *zap.SugaredLogger
}

func NewCveStoreRepositoryImpl(dbConnection *pg.DB, logger *zap.SugaredLogger) *CveStoreRepositoryImpl {
	return &CveStoreRepositoryImpl{
		dbConnection: dbConnection,
		logger:       logger,
	}
}

func (impl CveStoreRepositoryImpl) Save(model *CveStore) error {
	err := impl.dbConnection.Insert(model)
	return err
}

func (impl CveStoreRepositoryImpl) FindAll() ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByCveNames(names []string) ([]*CveStore, error) {
	var models []*CveStore
	err := impl.dbConnection.Model(&models).Where("name in (?)", pg.In(names)).Select()
	return models, err
}

func (impl CveStoreRepositoryImpl) FindByName(name string) (*CveStore, error) {
	var model CveStore
	err := impl.dbConnection.Model(&model).
		Where("name = ?", name).Select()
	return &model, err
}

func (impl CveStoreRepositoryImpl) Update(team *CveStore) error {
	err := impl.dbConnection.Update(team)
	return err
}

func (impl CveStoreRepositoryImpl) VulnerabilityExposure(request *VulnerabilityRequest) ([]*VulnerabilityExposure, error) {
	var items []*VulnerabilityExposure
	var queryParams []interface{}
	query := `SELECT a.id as app_id, a.app_name, a.app_type, p.environment_id as pipeline_env_id, ia.environment_id  as chart_env_id 
			  FROM app a 
			  LEFT JOIN pipeline p ON p.app_id=a.id 
			  LEFT JOIN installed_apps ia ON ia.app_id=a.id 
			  INNER JOIN environment env ON (env.id=p.environment_id OR env.id=ia.environment_id) 
			  WHERE (p.deleted=? OR ia.active = ?) and env.active=? `
	queryParams = append(queryParams, false, true, true)
	if len(request.AppName) > 0 {
		query = query + " AND (a.app_name ilike ? ) "
		queryParams = append(queryParams, util.GetLIKEClauseQueryParam(request.AppName))
	}
	if len(request.EnvIds) > 0 {
		query = query + " AND (env.id IN (?) )"
		queryParams = append(queryParams, pg.In(request.EnvIds))
	}
	if len(request.ClusterIds) > 0 {
		query = query + " AND (env.cluster_id IN (?) )"
		queryParams = append(queryParams, pg.In(request.ClusterIds))
	}
	query = query + " ORDER BY a.id DESC"
	if request.Size > 0 {
		query = query + " LIMIT ? OFFSET ? "
		queryParams = append(queryParams, request.Size, request.Offset)
	}
	query = query + " ;"
	impl.logger.Debugw("query", "query:", query)
	_, err := impl.dbConnection.Query(&items, query, queryParams...)
	if err != nil {
		impl.logger.Error("err", err)
		return []*VulnerabilityExposure{}, err
	}
	return items, err
}
