/*
 * Copyright (c) 2024. Devtron Inc.
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

package chartRepoRepository

import (
	"github.com/devtron-labs/devtron/internal/sql/models"
	"github.com/devtron-labs/devtron/pkg/sql"
	"github.com/go-pg/pg"
)

type Chart struct {
	tableName               struct{}                    `sql:"charts" pg:",discard_unknown_columns"`
	Id                      int                         `sql:"id,pk"`
	AppId                   int                         `sql:"app_id"`
	ChartRepoId             int                         `sql:"chart_repo_id"`
	ChartName               string                      `sql:"chart_name"` //use composite key as unique id
	ChartVersion            string                      `sql:"chart_version"`
	ChartRepo               string                      `sql:"chart_repo"`
	ChartRepoUrl            string                      `sql:"chart_repo_url"`
	Values                  string                      `sql:"values_yaml"`              //json format // used at for release. this should be always updated
	GlobalOverride          string                      `sql:"global_override"`          //json format    // global overrides visible to user only
	ReleaseOverride         string                      `sql:"release_override,notnull"` //json format   //image descriptor template used for injecting tigger metadata injection
	PipelineOverride        string                      `sql:"pipeline_override"`        //json format  // pipeline values -> strategy values
	Status                  models.ChartStatus          `sql:"status"`                   //(new , deployment-in-progress, deployed-To-production, error )
	Active                  bool                        `sql:"active"`
	GitRepoUrl              string                      `sql:"git_repo_url"`   // Deprecated;  use deployment_config table instead   //git repository where chart is stored
	ChartLocation           string                      `sql:"chart_location"` // Deprecated; location within git repo where current chart is pointing
	ReferenceTemplate       string                      `sql:"reference_template"`
	ImageDescriptorTemplate string                      `sql:"image_descriptor_template"`
	ChartRefId              int                         `sql:"chart_ref_id"`
	Latest                  bool                        `sql:"latest,notnull"`
	Previous                bool                        `sql:"previous,notnull"`
	ReferenceChart          []byte                      `sql:"reference_chart"`
	IsBasicViewLocked       bool                        `sql:"is_basic_view_locked,notnull"`
	CurrentViewEditor       models.ChartsViewEditorType `sql:"current_view_editor"`
	IsCustomGitRepository   bool                        `sql:"is_custom_repository"` // Deprecated;  use deployment_config table instead
	ResolvedGlobalOverride  string                      `sql:"-"`
	sql.AuditLog
}

type ChartRepository interface {
	//ChartReleasedToProduction(chartRepo, appName, chartVersion string) (bool, error)
	FindOne(chartRepo, appName, chartVersion string) (*Chart, error)
	Save(*Chart) error
	FindCurrentChartVersion(chartRepo, chartName, chartVersionPattern string) (string, error)
	FindActiveChart(appId int) (chart *Chart, err error)
	FindLatestByAppId(appId int) (chart *Chart, err error)
	FindById(id int) (chart *Chart, err error)
	Update(chart *Chart) error
	UpdateAllInTx(tx *pg.Tx, charts []*Chart) error

	FindActiveChartsByAppId(appId int) (charts []*Chart, err error)
	FindLatestChartForAppByAppId(appId int) (chart *Chart, err error)
	FindLatestChartByAppIds(appId []int) (chart []*Chart, err error)
	FindChartRefIdForLatestChartForAppByAppId(appId int) (int, error)
	FindChartByAppIdAndRefId(appId int, chartRefId int) (chart *Chart, err error)
	FindNoLatestChartForAppByAppId(appId int) ([]*Chart, error)
	FindPreviousChartByAppId(appId int) (chart *Chart, err error)
	FindNumberOfAppsWithDeploymentTemplate(appIds []int) (int, error)
	FindChartByGitRepoUrl(gitRepoUrl string) (*Chart, error)
	sql.TransactionWrapper
}

func NewChartRepository(dbConnection *pg.DB, TransactionUtilImpl *sql.TransactionUtilImpl) *ChartRepositoryImpl {
	return &ChartRepositoryImpl{
		dbConnection:        dbConnection,
		TransactionUtilImpl: TransactionUtilImpl,
	}
}

type ChartRepositoryImpl struct {
	dbConnection *pg.DB
	*sql.TransactionUtilImpl
}

func (repositoryImpl ChartRepositoryImpl) FindOne(chartRepo, chartName, chartVersion string) (*Chart, error) {
	chart := &Chart{}
	err := repositoryImpl.dbConnection.
		Model(chart).
		Where("chart_name= ?", chartName).
		Where("chart_version = ?", chartVersion).
		Where("chart_repo = ? ", chartRepo).
		Select()
	return chart, err
}
func (repositoryImpl ChartRepositoryImpl) FindCurrentChartVersion(chartRepo, chartName, chartVersionPattern string) (string, error) {
	chart := &Chart{}
	err := repositoryImpl.dbConnection.
		Model(chart).
		Where("chart_name= ?", chartName).
		Where("chart_version like ?", chartVersionPattern+"%").
		Where("chart_repo = ? ", chartRepo).
		Order("id Desc").
		Limit(1).
		Select()
	return chart.ChartVersion, err
}

// Deprecated
func (repositoryImpl ChartRepositoryImpl) FindActiveChart(appId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Where("active =?", true).
		Select()
	return chart, err
}

// Deprecated
func (repositoryImpl ChartRepositoryImpl) FindLatestByAppId(appId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindActiveChartsByAppId(appId int) (charts []*Chart, err error) {
	var activeCharts []*Chart
	err = repositoryImpl.dbConnection.
		Model(&activeCharts).
		Where("app_id= ?", appId).
		Where("active= ?", true).
		Select()
	return activeCharts, err
}

func (repositoryImpl ChartRepositoryImpl) FindLatestChartForAppByAppId(appId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Where("latest= ?", true).
		Select()
	return chart, err
}
func (repositoryImpl ChartRepositoryImpl) FindLatestChartByAppIds(appIds []int) ([]*Chart, error) {
	var chart []*Chart
	if len(appIds) == 0 {
		return nil, nil
	}
	err := repositoryImpl.dbConnection.
		Model(&chart).
		Where("app_id in (?)", pg.In(appIds)).
		Where("latest= ?", true).
		Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindChartRefIdForLatestChartForAppByAppId(appId int) (int, error) {
	chart := &Chart{}
	err := repositoryImpl.dbConnection.
		Model(chart).
		Column("chart_ref_id").
		Where("app_id= ?", appId).
		Where("latest= ?", true).
		Select()
	return chart.ChartRefId, err
}

func (repositoryImpl ChartRepositoryImpl) FindChartByAppIdAndRefId(appId int, chartRefId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Where("chart_ref_id= ?", chartRefId).
		Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindNoLatestChartForAppByAppId(appId int) ([]*Chart, error) {
	var charts []*Chart
	err := repositoryImpl.dbConnection.
		Model(&charts).
		Where("app_id= ?", appId).
		Where("latest= ?", false).
		Select()
	return charts, err
}

func (repositoryImpl ChartRepositoryImpl) FindLatestChartForAppByAppIdAndEnvId(appId int, envId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Where("latest= ?", true).
		Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindPreviousChartByAppId(appId int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.
		Model(chart).
		Where("app_id= ?", appId).
		Where("previous= ?", true).
		Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) Save(chart *Chart) error {
	return repositoryImpl.dbConnection.Insert(chart)
}

func (repositoryImpl ChartRepositoryImpl) Update(chart *Chart) error {
	_, err := repositoryImpl.dbConnection.Model(chart).WherePK().UpdateNotNull()
	return err
}

func (repositoryImpl ChartRepositoryImpl) UpdateAllInTx(tx *pg.Tx, charts []*Chart) error {
	for _, chart := range charts {
		_, err := tx.Model(chart).WherePK().UpdateNotNull()
		if err != nil {
			return err
		}
	}
	return nil
}

func (repositoryImpl ChartRepositoryImpl) FindById(id int) (chart *Chart, err error) {
	chart = &Chart{}
	err = repositoryImpl.dbConnection.Model(chart).
		Where("id = ?", id).Select()
	return chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindChartByGitRepoUrl(gitRepoUrl string) (*Chart, error) {
	var chart Chart
	err := repositoryImpl.dbConnection.Model(&chart).
		Join("INNER JOIN app ON app.id=app_id").
		Join("LEFT JOIN deployment_config dc on dc.active=true and dc.app_id = chart.app_id and dc.environment_id is null").
		Where("app.active = ?", true).
		Where("(chart.git_repo_url = ? or dc.repo_url = ?)", gitRepoUrl, gitRepoUrl).
		Where("chart.active = ?", true).
		Limit(1).
		Select()
	return &chart, err
}

func (repositoryImpl ChartRepositoryImpl) FindNumberOfAppsWithDeploymentTemplate(appIds []int) (int, error) {
	var charts []*Chart
	count, err := repositoryImpl.dbConnection.
		Model(&charts).
		ColumnExpr("DISTINCT app_id").
		Where("app_id in (?)", pg.In(appIds)).
		Count()
	if err != nil {
		return 0, err
	}

	return count, nil
}
