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

package pipeline

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	constants2 "github.com/devtron-labs/devtron/internal/sql/constants"
	attributesBean "github.com/devtron-labs/devtron/pkg/attributes/bean"
	adapter2 "github.com/devtron-labs/devtron/pkg/bean/adapter"
	common2 "github.com/devtron-labs/devtron/pkg/bean/common"
	repository6 "github.com/devtron-labs/devtron/pkg/build/git/gitMaterial/repository"
	"github.com/devtron-labs/devtron/pkg/build/pipeline"
	bean2 "github.com/devtron-labs/devtron/pkg/build/pipeline/bean"
	buildCommonBean "github.com/devtron-labs/devtron/pkg/build/pipeline/bean/common"
	read2 "github.com/devtron-labs/devtron/pkg/chart/read"
	repository2 "github.com/devtron-labs/devtron/pkg/cluster/environment/repository"
	"github.com/devtron-labs/devtron/pkg/deployment/common"
	"github.com/devtron-labs/devtron/pkg/deployment/common/read"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/config"
	util4 "github.com/devtron-labs/devtron/pkg/pipeline/util"
	"github.com/devtron-labs/devtron/pkg/plugin"
	"github.com/devtron-labs/devtron/util/beHelper"
	"github.com/devtron-labs/devtron/util/sliceUtil"
	"golang.org/x/exp/slices"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devtron-labs/devtron/pkg/pipeline/adapter"
	"github.com/devtron-labs/devtron/util/response/pagination"
	"go.opentelemetry.io/otel"

	util3 "github.com/devtron-labs/common-lib/utils/k8s"
	apiBean "github.com/devtron-labs/devtron/api/bean"
	"github.com/devtron-labs/devtron/client/gitSensor"
	app2 "github.com/devtron-labs/devtron/internal/sql/repository/app"
	dockerRegistryRepository "github.com/devtron-labs/devtron/internal/sql/repository/dockerRegistry"
	"github.com/devtron-labs/devtron/internal/sql/repository/helper"
	"github.com/devtron-labs/devtron/pkg/auth/authorisation/casbin"
	"github.com/devtron-labs/devtron/pkg/auth/user"
	bean3 "github.com/devtron-labs/devtron/pkg/auth/user/bean"
	"github.com/devtron-labs/devtron/pkg/chart"
	"github.com/devtron-labs/devtron/pkg/genericNotes"
	repository3 "github.com/devtron-labs/devtron/pkg/genericNotes/repository"
	pipelineConfigBean "github.com/devtron-labs/devtron/pkg/pipeline/bean"
	history3 "github.com/devtron-labs/devtron/pkg/pipeline/history"
	repository4 "github.com/devtron-labs/devtron/pkg/pipeline/history/repository"
	repository5 "github.com/devtron-labs/devtron/pkg/pipeline/repository"
	"github.com/devtron-labs/devtron/pkg/pipeline/types"
	"github.com/devtron-labs/devtron/pkg/sql"
	util2 "github.com/devtron-labs/devtron/util"

	"github.com/devtron-labs/devtron/internal/constants"
	"github.com/devtron-labs/devtron/internal/sql/repository"
	"github.com/devtron-labs/devtron/internal/sql/repository/appWorkflow"
	"github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig"
	"github.com/devtron-labs/devtron/internal/util"
	"github.com/devtron-labs/devtron/pkg/app"
	"github.com/devtron-labs/devtron/pkg/attributes"
	"github.com/devtron-labs/devtron/pkg/bean"
	"github.com/go-pg/pg"
	errors1 "github.com/juju/errors"
	"go.uber.org/zap"
)

type CiCdPipelineOrchestrator interface {
	CreateApp(createRequest *bean.CreateAppDTO) (*bean.CreateAppDTO, error)
	DeleteApp(appId int, userId int32) error
	CreateMaterials(createMaterialRequest *bean.CreateMaterialDTO) (*bean.CreateMaterialDTO, error)
	UpdateMaterial(updateMaterialRequest *bean.UpdateMaterialDTO) (*bean.UpdateMaterialDTO, error)
	CreateCiConf(createRequest *bean.CiConfigRequest, templateId int) (*bean.CiConfigRequest, error)
	CreateCDPipelines(pipelineRequest *bean.CDPipelineConfigObject, appId int, userId int32, tx *pg.Tx, appName string) (pipelineId int, err error)
	UpdateCDPipeline(pipelineRequest *bean.CDPipelineConfigObject, userId int32, tx *pg.Tx) (pipeline *pipelineConfig.Pipeline, err error)
	DeleteCiPipeline(pipeline *pipelineConfig.CiPipeline, request *bean.CiPatchRequest, tx *pg.Tx) error
	DeleteCiPipelineAndCiEnvMappings(tx *pg.Tx, ciPipeline *pipelineConfig.CiPipeline, userId int32) error
	SaveHistoryOfBaseTemplate(userId int32, pipeline *pipelineConfig.CiPipeline, materials []*pipelineConfig.CiPipelineMaterial) error
	DeleteCdPipeline(pipelineId int, userId int32, tx *pg.Tx) error
	PatchMaterialValue(createRequest *bean.CiPipeline, userId int32, oldPipeline *pipelineConfig.CiPipeline) (*bean.CiPipeline, error)
	PatchCiMaterialSource(ciPipeline *bean.CiMaterialPatchRequest, userId int32) (*bean.CiMaterialPatchRequest, error)
	PatchCiMaterialSourceValue(patchRequest *bean.CiMaterialValuePatchRequest, userId int32, value string, token string, checkAppSpecificAccess func(token, action string, appId int) (bool, error)) (*pipelineConfig.CiPipelineMaterial, error)
	CreateCiTemplateBean(ciPipelineId int, dockerRegistryId string, dockerRepository string, gitMaterialId int, ciBuildConfig *bean2.CiBuildConfigBean, userId int32) bean2.CiTemplateBean
	UpdateCiPipelineMaterials(materialsUpdate []*pipelineConfig.CiPipelineMaterial) error
	PipelineExists(name string) (bool, error)
	GetCdPipelinesForApp(appId int) (cdPipelines *bean.CdPipelines, err error)
	GetCdPipelinesForAppAndEnv(appId int, envId int) (cdPipelines *bean.CdPipelines, err error)
	GetByEnvOverrideId(envOverrideId int) (*bean.CdPipelines, error)
	BuildCiPipelineScript(userId int32, ciScript *bean.CiScript, scriptStage string, ciPipeline *bean.CiPipeline) *pipelineConfig.CiPipelineScript
	AddPipelineMaterialInGitSensor(pipelineMaterials []*pipelineConfig.CiPipelineMaterial) error
	CheckStringMatchRegex(regex string, value string) bool
	CreateEcrRepo(dockerRepository, AWSRegion, AWSAccessKeyId, AWSSecretAccessKey string) error
	GetCdPipelinesForEnv(envId int, requestedAppIds []int) (cdPipelines *bean.CdPipelines, err error)
	AddPipelineToTemplate(createRequest *bean.CiConfigRequest, isSwitchCiPipelineRequest bool) (resp *bean.CiConfigRequest, err error)
	GetSourceCiDownStreamFilters(ctx context.Context, sourceCiPipelineId int) (*bean2.SourceCiDownStreamEnv, error)
	GetSourceCiDownStreamInfo(ctx context.Context, sourceCIPipeline int, req *bean2.SourceCiDownStreamFilters) (pagination.PaginatedResponse[bean2.SourceCiDownStreamResponse], error)
	GetSourceCiPipelineForArtifact(ciPipeline pipelineConfig.CiPipeline) (*pipelineConfig.CiPipeline, error)
	GetGitCommitEnvVarDataForCICDStage(gitTriggers map[int]pipelineConfig.GitCommit) (map[string]string, *gitSensor.WebhookAndCiData, error)
	GetWorkflowCacheConfig(appType helper.AppType, pipelineType string, pipelineWorkflowCacheConfig common2.WorkflowCacheConfigType) bean.WorkflowCacheConfig
}

type CiCdPipelineOrchestratorImpl struct {
	appRepository                 app2.AppRepository
	logger                        *zap.SugaredLogger
	materialRepository            repository6.MaterialRepository
	pipelineRepository            pipelineConfig.PipelineRepository
	ciPipelineRepository          pipelineConfig.CiPipelineRepository
	ciPipelineMaterialRepository  pipelineConfig.CiPipelineMaterialRepository
	cdWorkflowRepository          pipelineConfig.CdWorkflowRepository
	GitSensorClient               gitSensor.Client
	ciConfig                      *types.CiCdConfig
	appWorkflowRepository         appWorkflow.AppWorkflowRepository
	envRepository                 repository2.EnvironmentRepository
	attributesService             attributes.AttributesService
	appLabelsService              app.AppCrudOperationService
	userAuthService               user.UserAuthService
	prePostCdScriptHistoryService history3.PrePostCdScriptHistoryService
	pipelineStageService          PipelineStageService
	ciTemplateReadService         pipeline.CiTemplateReadService
	ciTemplateService             CiTemplateService
	gitMaterialHistoryService     history3.GitMaterialHistoryService
	ciPipelineHistoryService      history3.CiPipelineHistoryService
	dockerArtifactStoreRepository dockerRegistryRepository.DockerArtifactStoreRepository
	CiArtifactRepository          repository.CiArtifactRepository
	configMapService              ConfigMapService
	genericNoteService            genericNotes.GenericNoteService
	customTagService              CustomTagService
	chartService                  chart.ChartService
	transactionManager            sql.TransactionWrapper
	gitOpsConfigReadService       config.GitOpsConfigReadService
	deploymentConfigService       common.DeploymentConfigService
	deploymentConfigReadService   read.DeploymentConfigReadService
	workflowCacheConfig           types.WorkflowCacheConfig
	chartReadService              read2.ChartReadService
}

func NewCiCdPipelineOrchestrator(
	pipelineGroupRepository app2.AppRepository,
	logger *zap.SugaredLogger,
	materialRepository repository6.MaterialRepository,
	pipelineRepository pipelineConfig.PipelineRepository,
	ciPipelineRepository pipelineConfig.CiPipelineRepository,
	ciPipelineMaterialRepository pipelineConfig.CiPipelineMaterialRepository,
	cdWorkflowRepository pipelineConfig.CdWorkflowRepository,
	GitSensorClient gitSensor.Client, ciConfig *types.CiCdConfig,
	appWorkflowRepository appWorkflow.AppWorkflowRepository,
	envRepository repository2.EnvironmentRepository,
	attributesService attributes.AttributesService,
	appLabelsService app.AppCrudOperationService,
	userAuthService user.UserAuthService,
	prePostCdScriptHistoryService history3.PrePostCdScriptHistoryService,
	pipelineStageService PipelineStageService,
	gitMaterialHistoryService history3.GitMaterialHistoryService,
	ciPipelineHistoryService history3.CiPipelineHistoryService,
	ciTemplateReadService pipeline.CiTemplateReadService,
	ciTemplateService CiTemplateService,
	dockerArtifactStoreRepository dockerRegistryRepository.DockerArtifactStoreRepository,
	CiArtifactRepository repository.CiArtifactRepository,
	configMapService ConfigMapService,
	customTagService CustomTagService,
	genericNoteService genericNotes.GenericNoteService,
	chartService chart.ChartService, transactionManager sql.TransactionWrapper,
	gitOpsConfigReadService config.GitOpsConfigReadService,
	deploymentConfigService common.DeploymentConfigService,
	deploymentConfigReadService read.DeploymentConfigReadService,
	chartReadService read2.ChartReadService) *CiCdPipelineOrchestratorImpl {
	_, workflowCacheConfig, err := types.GetCiConfigWithWorkflowCacheConfig()
	if err != nil {
		logger.Errorw("Error in getting workflow cache config, continuing with default values", "err", err)
	}
	return &CiCdPipelineOrchestratorImpl{
		appRepository:                 pipelineGroupRepository,
		logger:                        logger,
		materialRepository:            materialRepository,
		pipelineRepository:            pipelineRepository,
		ciPipelineRepository:          ciPipelineRepository,
		ciPipelineMaterialRepository:  ciPipelineMaterialRepository,
		cdWorkflowRepository:          cdWorkflowRepository,
		GitSensorClient:               GitSensorClient,
		ciConfig:                      ciConfig,
		appWorkflowRepository:         appWorkflowRepository,
		envRepository:                 envRepository,
		attributesService:             attributesService,
		appLabelsService:              appLabelsService,
		userAuthService:               userAuthService,
		prePostCdScriptHistoryService: prePostCdScriptHistoryService,
		pipelineStageService:          pipelineStageService,
		gitMaterialHistoryService:     gitMaterialHistoryService,
		ciPipelineHistoryService:      ciPipelineHistoryService,
		ciTemplateReadService:         ciTemplateReadService,
		ciTemplateService:             ciTemplateService,
		dockerArtifactStoreRepository: dockerArtifactStoreRepository,
		CiArtifactRepository:          CiArtifactRepository,
		configMapService:              configMapService,
		genericNoteService:            genericNoteService,
		customTagService:              customTagService,
		chartService:                  chartService,
		transactionManager:            transactionManager,
		gitOpsConfigReadService:       gitOpsConfigReadService,
		deploymentConfigService:       deploymentConfigService,
		deploymentConfigReadService:   deploymentConfigReadService,
		workflowCacheConfig:           workflowCacheConfig,
		chartReadService:              chartReadService,
	}
}

func (impl CiCdPipelineOrchestratorImpl) PatchCiMaterialSource(patchRequest *bean.CiMaterialPatchRequest, userId int32) (*bean.CiMaterialPatchRequest, error) {
	pipeline, err := impl.findUniquePipelineForAppIdAndEnvironmentId(patchRequest.AppId, patchRequest.EnvironmentId)
	if err != nil {
		return nil, err
	}
	ciPipelineMaterial, err := impl.findUniqueCiPipelineMaterial(pipeline.CiPipelineId)
	if err != nil {
		return nil, err
	}
	ciPipelineMaterial.Type = patchRequest.Source.Type
	ciPipelineMaterial.Value = patchRequest.Source.Value
	ciPipelineMaterial.Regex = patchRequest.Source.Regex
	ciPipelineMaterial.AuditLog.UpdatedBy = userId
	ciPipelineMaterial.AuditLog.UpdatedOn = time.Now()
	if err = impl.saveUpdatedMaterial([]*pipelineConfig.CiPipelineMaterial{ciPipelineMaterial}); err != nil {
		return nil, err
	}
	return patchRequest, nil
}

func (impl CiCdPipelineOrchestratorImpl) PatchCiMaterialSourceValue(patchRequest *bean.CiMaterialValuePatchRequest, userId int32, value string, token string, checkAppSpecificAccess func(token, action string, appId int) (bool, error)) (*pipelineConfig.CiPipelineMaterial, error) {
	pipeline, err := impl.findUniquePipelineForAppIdAndEnvironmentId(patchRequest.AppId, patchRequest.EnvironmentId)
	if err != nil {
		impl.logger.Errorw("Error in getting UniquePipelineForAppIdAndEnvironmentId", "appId", patchRequest.AppId, "envId", patchRequest.EnvironmentId, "err", err)
		return nil, err
	}
	appWorkflowMapping, err := impl.appWorkflowRepository.GetParentDetailsByPipelineId(pipeline.Id)
	if err != nil {
		impl.logger.Errorw("failed to get parent component details",
			"componentId", pipeline.Id,
			"err", err)
		return nil, err
	}
	if appWorkflowMapping.ParentType == appWorkflow.WEBHOOK {
		return nil, errors.New(string(bean.CI_PATCH_SKIP_MESSAGE) + "“Webhook”")
	}
	ciPipelineMaterial, err := impl.findUniqueCiPipelineMaterial(pipeline.CiPipelineId)
	if err != nil {
		impl.logger.Errorw("Error in getting UniqueCiPipelineMaterial", "CiPipelineId", pipeline.CiPipelineId, "err", err)
		if strings.Contains(err.Error(), "ciPipelineMaterial not found") {
			return nil, errors.New(string(bean.CI_BRANCH_TYPE_ERROR))
		}
		return nil, err
	}

	err = impl.validateCiPipelineMaterial(ciPipelineMaterial, value, token, checkAppSpecificAccess, patchRequest.AppId)
	if err != nil {
		impl.logger.Errorw("Validation failed on CiPipelineMaterial", "err", err)
		return nil, err
	}

	ciPipelineMaterial.Value = value
	ciPipelineMaterial.AuditLog.UpdatedBy = userId
	ciPipelineMaterial.AuditLog.UpdatedOn = time.Now()
	return ciPipelineMaterial, nil
}

func (impl CiCdPipelineOrchestratorImpl) UpdateCiPipelineMaterials(materialsUpdate []*pipelineConfig.CiPipelineMaterial) error {
	if err := impl.saveUpdatedMaterial(materialsUpdate); err != nil {
		return err
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) validateCiPipelineMaterial(ciPipelineMaterial *pipelineConfig.CiPipelineMaterial, value string, token string, checkAppSpecificAccess func(token, action string, appId int) (bool, error), appId int) error {
	// Change branch source is supported for SOURCE_TYPE_BRANCH_FIXED and SOURCE_TYPE_BRANCH_REGEX
	if ciPipelineMaterial.Type != constants2.SOURCE_TYPE_BRANCH_FIXED && ciPipelineMaterial.Type != constants2.SOURCE_TYPE_BRANCH_REGEX {
		return errors.New(string(bean.CI_BRANCH_TYPE_ERROR))
	}

	if ciPipelineMaterial.CiPipeline.ParentCiPipeline != 0 {
		return errors.New(string(bean.CI_PATCH_SKIP_MESSAGE) + impl.getSkipMessage(ciPipelineMaterial.CiPipeline))
	}
	if ciPipelineMaterial.Regex != "" {
		// Checking CiTriggerRequest Access for Regex branch
		if ok, err := checkAppSpecificAccess(token, casbin.ActionTrigger, appId); !ok {
			return err
		}
	} else {
		// Checking Admin Access for Fixed branch
		if ok, err := checkAppSpecificAccess(token, casbin.ActionUpdate, appId); !ok {
			return err
		}
	}

	// In case of regex we are check if the branch match the regex
	if ciPipelineMaterial.Regex != "" {
		ok, err := regexp.MatchString(ciPipelineMaterial.Regex, value)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New(string(bean.CI_PATCH_REGEX_ERROR) + "“" + ciPipelineMaterial.Regex + "”")
		}
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) getSkipMessage(ciPipeline *pipelineConfig.CiPipeline) string {
	switch ciPipeline.PipelineType {
	case string(buildCommonBean.LINKED_CD):
		return "“Sync with Environment”"
	default:
		return "“Linked Build Pipeline”"
	}
}

func (impl CiCdPipelineOrchestratorImpl) findUniquePipelineForAppIdAndEnvironmentId(appId, environmentId int) (*pipelineConfig.Pipeline, error) {
	pipeline, err := impl.pipelineRepository.FindActiveByAppIdAndEnvironmentId(appId, environmentId)
	if err != nil {
		return nil, err
	}
	if len(pipeline) != 1 {
		return nil, fmt.Errorf("unique pipeline was not found, for the given appId and environmentId")
	}
	return pipeline[0], nil
}

func (impl CiCdPipelineOrchestratorImpl) findUniqueCiPipelineMaterial(ciPipelineId int) (*pipelineConfig.CiPipelineMaterial, error) {
	ciPipelineMaterials, err := impl.ciPipelineMaterialRepository.FindByCiPipelineIdsIn([]int{ciPipelineId})
	if err != nil {
		return nil, err
	}
	if ciPipelineMaterials == nil {
		return nil, fmt.Errorf("ciPipelineMaterial not found")
	}
	if len(ciPipelineMaterials) != 1 {
		return nil, fmt.Errorf(string(bean.CI_PATCH_MULTI_GIT_ERROR))
	}
	return ciPipelineMaterials[0], nil
}

func (impl CiCdPipelineOrchestratorImpl) saveUpdatedMaterial(materialsUpdate []*pipelineConfig.CiPipelineMaterial) error {
	dbConnection := impl.pipelineRepository.GetConnection()
	tx, err := dbConnection.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = impl.ciPipelineMaterialRepository.Update(tx, materialsUpdate...); err != nil {
		return err
	}
	if err = impl.AddPipelineMaterialInGitSensor(materialsUpdate); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}
func (impl CiCdPipelineOrchestratorImpl) PatchMaterialValue(createRequest *bean.CiPipeline, userId int32, oldPipeline *pipelineConfig.CiPipeline) (*bean.CiPipeline, error) {
	argByte, err := json.Marshal(createRequest.DockerArgs)
	if err != nil {
		impl.logger.Error(err)
		return nil, err
	}
	dbConnection := impl.pipelineRepository.GetConnection()
	tx, err := dbConnection.Begin()
	if err != nil {
		return nil, err
	}
	// Rollback tx on error.
	defer tx.Rollback()
	ciPipelineObject := &pipelineConfig.CiPipeline{
		Version:                  createRequest.Version,
		Id:                       createRequest.Id,
		DockerArgs:               string(argByte),
		Active:                   createRequest.Active,
		IsManual:                 createRequest.IsManual,
		IsExternal:               createRequest.IsExternal,
		Deleted:                  createRequest.Deleted,
		ParentCiPipeline:         createRequest.ParentCiPipeline,
		ScanEnabled:              createRequest.ScanEnabled,
		IsDockerConfigOverridden: createRequest.IsDockerConfigOverridden,
		AuditLog:                 sql.AuditLog{UpdatedBy: userId, UpdatedOn: time.Now()},
	}

	if createRequest.EnableCustomTag && len(createRequest.CustomTagObject.TagPattern) == 0 {
		return nil, errors.New("please input custom tag data if tag is enabled")
	}

	//If customTagObject has been passed, create or update the resource
	//Otherwise deleteIfExists
	if createRequest.CustomTagObject != nil && len(createRequest.CustomTagObject.TagPattern) > 0 {
		customTag := apiBean.CustomTag{
			EntityKey:            pipelineConfigBean.EntityTypeCiPipelineId,
			EntityValue:          strconv.Itoa(ciPipelineObject.Id),
			TagPattern:           createRequest.CustomTagObject.TagPattern,
			AutoIncreasingNumber: createRequest.CustomTagObject.CounterX,
			Enabled:              createRequest.EnableCustomTag,
		}
		err = impl.customTagService.CreateOrUpdateCustomTag(&customTag)
		if err != nil {
			return nil, err
		}
	} else {
		customTag := apiBean.CustomTag{
			EntityKey:   pipelineConfigBean.EntityTypeCiPipelineId,
			EntityValue: strconv.Itoa(ciPipelineObject.Id),
			Enabled:     false,
		}
		err := impl.customTagService.DeleteCustomTagIfExists(customTag)
		if err != nil {
			return nil, err
		}
	}

	createOnTimeMap := make(map[int]time.Time)
	createByMap := make(map[int]int32)
	for _, oldMaterial := range oldPipeline.CiPipelineMaterials {
		createOnTimeMap[oldMaterial.GitMaterialId] = oldMaterial.CreatedOn
		createByMap[oldMaterial.GitMaterialId] = oldMaterial.CreatedBy
	}

	err = impl.ciPipelineRepository.Update(ciPipelineObject, tx)
	if err != nil {
		return nil, err
	}
	var CiEnvMappingObject *pipelineConfig.CiEnvMapping
	if ciPipelineObject.Id != 0 {
		CiEnvMappingObject, err = impl.ciPipelineRepository.FindCiEnvMappingByCiPipelineId(ciPipelineObject.Id)
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("error in getting CiEnvMappingObject ", "err", err, "ciPipelineId", createRequest.Id)
			return nil, err
		}
	}
	if err == nil && CiEnvMappingObject != nil {
		if CiEnvMappingObject.EnvironmentId != createRequest.EnvironmentId {
			CiEnvMappingObject.EnvironmentId = createRequest.EnvironmentId
			CiEnvMappingObject.AuditLog = sql.AuditLog{UpdatedBy: userId, UpdatedOn: time.Now()}
			err = impl.ciPipelineRepository.UpdateCiEnvMapping(CiEnvMappingObject, tx)
			if err != nil {
				impl.logger.Errorw("error in getting CiEnvMappingObject ", "err", err, "ciPipelineId", createRequest.Id)
				return nil, err
			}
			if createRequest.EnvironmentId != 0 {
				createJobEnvOverrideRequest := &pipelineConfigBean.CreateJobEnvOverridePayload{
					AppId:  createRequest.AppId,
					EnvId:  createRequest.EnvironmentId,
					UserId: userId,
				}
				_, err = impl.configMapService.ConfigSecretEnvironmentCreate(createJobEnvOverrideRequest)
				if err != nil && !strings.Contains(err.Error(), "already exists") {
					impl.logger.Errorw("error in saving env override", "createJobEnvOverrideRequest", createJobEnvOverrideRequest, "err", err)
					return nil, err
				}
			}
		}
	}
	// marking old scripts inactive
	err = impl.ciPipelineRepository.MarkCiPipelineScriptsInactiveByCiPipelineId(createRequest.Id, tx)
	if err != nil {
		impl.logger.Errorw("error in marking ciPipelineScripts inactive", "err", err, "ciPipelineId", createRequest.Id)
		return nil, err
	}
	if createRequest.PreBuildStage != nil {
		//updating pre stage
		err = impl.pipelineStageService.UpdatePipelineStage(createRequest.PreBuildStage, repository5.PIPELINE_STAGE_TYPE_PRE_CI, createRequest.Id, userId)
		if err != nil {
			impl.logger.Errorw("error in updating pre stage", "err", err, "preBuildStage", createRequest.PreBuildStage, "ciPipelineId", createRequest.Id)
			return nil, err
		}
	}
	if createRequest.PostBuildStage != nil {
		//updating post stage
		err = impl.pipelineStageService.UpdatePipelineStage(createRequest.PostBuildStage, repository5.PIPELINE_STAGE_TYPE_POST_CI, createRequest.Id, userId)
		if err != nil {
			impl.logger.Errorw("error in updating post stage", "err", err, "postBuildStage", createRequest.PostBuildStage, "ciPipelineId", createRequest.Id)
			return nil, err
		}
	}
	for _, material := range createRequest.CiMaterial {
		if material.IsRegex == true && material.Source.Value != "" {
			material.IsRegex = false
		} else if material.IsRegex == false && material.Source.Regex != "" {
			material.IsRegex = true
		}
	}
	var materials []*pipelineConfig.CiPipelineMaterial
	var materialsAdd []*pipelineConfig.CiPipelineMaterial
	var materialsUpdate []*pipelineConfig.CiPipelineMaterial
	var materialGitMap = make(map[int]string)
	for _, material := range createRequest.CiMaterial {
		pipelineMaterial := &pipelineConfig.CiPipelineMaterial{
			Id:            material.Id,
			Value:         material.Source.Value,
			Type:          material.Source.Type,
			Active:        createRequest.Active,
			Regex:         material.Source.Regex,
			GitMaterialId: material.GitMaterialId,
			AuditLog:      sql.AuditLog{UpdatedBy: userId, UpdatedOn: time.Now()},
		}
		if material.Source.Type == constants2.SOURCE_TYPE_BRANCH_FIXED {
			materialGitMap[material.GitMaterialId] = material.Source.Value
		}
		if material.Id == 0 {
			pipelineMaterial.CiPipelineId = createRequest.Id
			pipelineMaterial.CreatedBy = userId
			pipelineMaterial.CreatedOn = time.Now()
			materialsAdd = append(materialsAdd, pipelineMaterial)
		} else {
			pipelineMaterial.CiPipelineId = createRequest.Id
			pipelineMaterial.CreatedBy = userId
			pipelineMaterial.CreatedOn = createOnTimeMap[material.GitMaterialId]
			pipelineMaterial.UpdatedOn = time.Now()
			pipelineMaterial.UpdatedBy = userId
			materialsUpdate = append(materialsUpdate, pipelineMaterial)
		}
	}
	if len(materialsAdd) > 0 {
		err = impl.ciPipelineMaterialRepository.Save(tx, materialsAdd...)
		if err != nil {
			return nil, err
		}
	}
	if len(materialsUpdate) > 0 {
		err = impl.ciPipelineMaterialRepository.Update(tx, materialsUpdate...)
		if err != nil {
			return nil, err
		}
	}

	materials = append(materials, materialsAdd...)
	materials = append(materials, materialsUpdate...)

	if ciPipelineObject.IsExternal {

	} else {
		err = impl.AddPipelineMaterialInGitSensor(materials)
		if err != nil {
			impl.logger.Errorf("error in saving pipelineMaterials in git sensor", "materials", materials, "err", err)
			return nil, err
		}
	}

	childrenCiPipelines, err := impl.ciPipelineRepository.FindByParentCiPipelineId(createRequest.Id)
	if err != nil && !util.IsErrNoRows(err) {
		impl.logger.Errorw("err", "err", err)
		return nil, err
	}
	var childrenCiPipelineIds []int
	for _, ci := range childrenCiPipelines {
		childrenCiPipelineIds = append(childrenCiPipelineIds, ci.Id)
		ciPipelineObject := &pipelineConfig.CiPipeline{
			Version:                  createRequest.Version,
			Id:                       ci.Id,
			DockerArgs:               string(argByte),
			Active:                   createRequest.Active,
			IsManual:                 createRequest.IsManual,
			IsExternal:               true,
			Deleted:                  createRequest.Deleted,
			ParentCiPipeline:         createRequest.Id,
			IsDockerConfigOverridden: createRequest.IsDockerConfigOverridden,
			AuditLog:                 sql.AuditLog{UpdatedBy: userId, UpdatedOn: time.Now()},
		}
		err = impl.ciPipelineRepository.Update(ciPipelineObject, tx)
		if err != nil {
			impl.logger.Errorw("err", "err", err)
			return nil, err
		}
	}
	if !createRequest.IsExternal && createRequest.IsDockerConfigOverridden {
		//get override
		savedTemplateOverrideBean, err := impl.ciTemplateReadService.FindTemplateOverrideByCiPipelineId(createRequest.Id)
		if err != nil && err != pg.ErrNoRows {
			impl.logger.Errorw("error in getting templateOverride by ciPipelineId", "err", err, "ciPipelineId", createRequest.Id)
			return nil, err
		}
		ciBuildConfigBean := createRequest.DockerConfigOverride.CiBuildConfig
		templateOverrideReq := &pipelineConfig.CiTemplateOverride{
			CiPipelineId:     createRequest.Id,
			DockerRegistryId: createRequest.DockerConfigOverride.DockerRegistry,
			DockerRepository: createRequest.DockerConfigOverride.DockerRepository,
			//DockerfilePath:   createRequest.DockerConfigOverride.DockerBuildConfig.DockerfilePath,
			GitMaterialId:             ciBuildConfigBean.GitMaterialId,
			BuildContextGitMaterialId: ciBuildConfigBean.BuildContextGitMaterialId,
			Active:                    true,
			AuditLog: sql.AuditLog{
				CreatedOn: time.Now(),
				CreatedBy: userId,
				UpdatedOn: time.Now(),
				UpdatedBy: userId,
			},
		}

		savedTemplateOverride := savedTemplateOverrideBean.CiTemplateOverride
		err = impl.createDockerRepoIfNeeded(createRequest.DockerConfigOverride.DockerRegistry, createRequest.DockerConfigOverride.DockerRepository)
		if err != nil {
			impl.logger.Errorw("error, createDockerRepoIfNeeded", "err", err, "dockerRegistryId", createRequest.DockerConfigOverride.DockerRegistry, "dockerRegistry", createRequest.DockerConfigOverride.DockerRepository)
			return nil, err
		}
		if savedTemplateOverride != nil && savedTemplateOverride.Id > 0 {
			ciBuildConfigBean.Id = savedTemplateOverride.CiBuildConfigId
			templateOverrideReq.Id = savedTemplateOverride.Id
			templateOverrideReq.CreatedOn = savedTemplateOverride.CreatedOn
			templateOverrideReq.CreatedBy = savedTemplateOverride.CreatedBy
			ciTemplateBean := &bean2.CiTemplateBean{
				CiTemplateOverride: templateOverrideReq,
				CiBuildConfig:      ciBuildConfigBean,
				UserId:             userId,
			}
			err = impl.ciTemplateService.Update(ciTemplateBean)
			if err != nil {
				return nil, err
			}

			err = impl.ciPipelineHistoryService.SaveHistory(ciPipelineObject, materials, ciTemplateBean, repository4.TRIGGER_UPDATE)

			if err != nil {
				impl.logger.Errorw("error in saving history of ci pipeline material")
			}

		} else {
			ciTemplateBean := &bean2.CiTemplateBean{
				CiTemplateOverride: templateOverrideReq,
				CiBuildConfig:      ciBuildConfigBean,
				UserId:             userId,
			}
			err := impl.ciTemplateService.Save(ciTemplateBean)
			if err != nil {
				return nil, err
			}

			err = impl.ciPipelineHistoryService.SaveHistory(ciPipelineObject, materials, ciTemplateBean, repository4.TRIGGER_UPDATE)

			if err != nil {
				impl.logger.Errorw("error in saving history of ci pipeline material")
			}

		}
	} else {
		ciTemplateBean := &bean2.CiTemplateBean{
			CiTemplateOverride: &pipelineConfig.CiTemplateOverride{},
			CiBuildConfig:      nil,
			UserId:             userId,
		}
		err = impl.ciPipelineHistoryService.SaveHistory(ciPipelineObject, materials, ciTemplateBean, repository4.TRIGGER_UPDATE)
		if err != nil {
			impl.logger.Errorw("error in saving history of ci pipeline material")
		}
	}

	err = impl.syncChildrenCiPipelineMaterialsWithParent(tx, childrenCiPipelineIds, createRequest.CiMaterial, userId)
	if err != nil {
		impl.logger.Errorw("error in syncing ci pipleine materials for linked child pipelines", "childrenCiPipelineIds", childrenCiPipelineIds, "err", err)
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return createRequest, nil
}

func (impl CiCdPipelineOrchestratorImpl) syncChildrenCiPipelineMaterialsWithParent(tx *pg.Tx, childrenCiPipelineIds []int, parentCiMaterials []*bean.CiMaterial, userId int32) error {
	if len(childrenCiPipelineIds) == 0 {
		return nil
	}

	childrenCiPipelineMaterials, err := impl.ciPipelineMaterialRepository.FindByCiPipelineIdsIn(childrenCiPipelineIds)
	if err != nil {
		impl.logger.Errorw("error in fetching  ciPipelineMaterials", "err", err)
		return err
	}

	childrenMaterialsMap := make(map[int][]*pipelineConfig.CiPipelineMaterial)
	for _, material := range childrenCiPipelineMaterials {
		if _, ok := childrenMaterialsMap[material.CiPipelineId]; !ok {
			childrenMaterialsMap[material.CiPipelineId] = make([]*pipelineConfig.CiPipelineMaterial, 0)
		}
		childrenMaterialsMap[material.CiPipelineId] = append(childrenMaterialsMap[material.CiPipelineId], material)
	}

	// context: linked-ci
	// we never come here for child

	var creatablePipelineMaterials, updatablePipelineMaterials []*pipelineConfig.CiPipelineMaterial
	for childPipelineId, childPipelineMaterials := range childrenMaterialsMap {
		creatableMaterials, updateMaterials := computeCreatableAndUpdatableMaterials(parentCiMaterials, childPipelineMaterials, childPipelineId, userId)
		creatablePipelineMaterials = append(creatablePipelineMaterials, creatableMaterials...)
		updatablePipelineMaterials = append(updatablePipelineMaterials, updateMaterials...)
	}

	if len(updatablePipelineMaterials) > 0 {
		err = impl.ciPipelineMaterialRepository.Update(tx, updatablePipelineMaterials...)
		if err != nil {
			impl.logger.Errorw("error in updating ci pipeline materials for linked child pipelines", "err", err, "updatablePipelineMaterials", updatablePipelineMaterials)
			return err
		}
	}

	if len(creatablePipelineMaterials) > 0 {
		err = impl.ciPipelineMaterialRepository.Save(tx, creatablePipelineMaterials...)
		if err != nil {
			impl.logger.Errorw("error in updating ci pipeline materials for linked child pipelines", "err", err, "updatablePipelineMaterials", updatablePipelineMaterials)
			return err
		}
	}

	return nil
}

func computeCreatableAndUpdatableMaterials(parentCiMaterials []*bean.CiMaterial, childMaterials []*pipelineConfig.CiPipelineMaterial, childPipelineId int, userId int32) ([]*pipelineConfig.CiPipelineMaterial, []*pipelineConfig.CiPipelineMaterial) {
	// for parent, three cases are possible

	// case-1: new git-material is added
	//	-> we cannot find this in child, but can be found at parent
	//     this should be added at child

	// case-2: existing material is updated
	//  -> we can find this in child and parent
	//     this should be updated at child

	// case-3: material was deleted
	//	-> we can find at child but cannot find at parent
	//     this should be deleted at child

	parentMaterialsMap := make(map[int]*bean.CiMaterial)
	for _, material := range parentCiMaterials {
		parentMaterialsMap[material.GitMaterialId] = material
	}

	childrenMaterialsMap := make(map[int]*pipelineConfig.CiPipelineMaterial)
	for _, material := range childMaterials {
		childrenMaterialsMap[material.GitMaterialId] = material
	}

	// compute updatable and deletable materials
	var updatableMaterials []*pipelineConfig.CiPipelineMaterial
	for _, ciPipelineMaterial := range childMaterials {
		// this material is found at parent , which means we can update this ciPipelineMaterial
		if parentMaterial, ok := parentMaterialsMap[ciPipelineMaterial.GitMaterialId]; ok {
			ciPipelineMaterial.Value = parentMaterial.Source.Value
			ciPipelineMaterial.Regex = parentMaterial.Source.Regex
			ciPipelineMaterial.Type = parentMaterial.Source.Type
			ciPipelineMaterial.GitMaterialId = parentMaterial.GitMaterialId
		} else {
			// this material is found at parent , which means we can delete this ciPipelineMaterial
			ciPipelineMaterial.Active = false
		}
		ciPipelineMaterial.UpdatedOn = time.Now()
		ciPipelineMaterial.UpdatedBy = userId
		updatableMaterials = append(updatableMaterials, ciPipelineMaterial)
	}

	// compute creatable materials
	var creatableMaterials []*pipelineConfig.CiPipelineMaterial
	for _, ciPipelineMaterial := range parentCiMaterials {
		// this material is not found at child , which means we should create this ciPipelineMaterial for child
		if _, ok := childrenMaterialsMap[ciPipelineMaterial.GitMaterialId]; !ok {
			creatableMaterial := &pipelineConfig.CiPipelineMaterial{
				Value:         ciPipelineMaterial.Source.Value,
				Active:        true,
				Regex:         ciPipelineMaterial.Source.Regex,
				AuditLog:      sql.NewDefaultAuditLog(userId),
				Type:          ciPipelineMaterial.Source.Type,
				GitMaterialId: ciPipelineMaterial.GitMaterialId,
				CiPipelineId:  childPipelineId,
			}
			creatableMaterials = append(creatableMaterials, creatableMaterial)
		}
	}

	return creatableMaterials, updatableMaterials

}

func (impl CiCdPipelineOrchestratorImpl) DeleteCiPipeline(pipeline *pipelineConfig.CiPipeline, request *bean.CiPatchRequest, tx *pg.Tx) error {

	userId := request.UserId
	err := impl.DeleteCiPipelineAndCiEnvMappings(tx, pipeline, userId)
	if err != nil {
		impl.logger.Errorw("error in deleting ciPipeline and ci-env mappings", "err", err, "pipelineId", pipeline.Id)
		return err
	}
	var materials []*pipelineConfig.CiPipelineMaterial
	for _, material := range pipeline.CiPipelineMaterials {
		materialDbObject, err := impl.ciPipelineMaterialRepository.GetById(material.Id)
		if err != nil {
			return err
		}
		materialDbObject.Active = false
		materials = append(materials, materialDbObject)
	}

	if request.CiPipeline.ExternalCiConfig.Id != 0 {
		err = impl.AddPipelineMaterialInGitSensor(materials)
		if err != nil {
			impl.logger.Errorw("error in saving pipelineMaterials in git sensor", "materials", materials, "err", err)
			return err
		}
	}
	if len(materials) > 0 {
		err = impl.ciPipelineMaterialRepository.Update(tx, materials...)
		if err != nil {
			impl.logger.Errorw("error in updating ci pipeline materials, DeleteCiPipeline", "err", err, "pipelineId", pipeline.Id)
			return err
		}
	}

	if !request.CiPipeline.IsDockerConfigOverridden || request.CiPipeline.IsExternal { //if pipeline is external or if config is not overridden then ignore override and ciBuildConfig values
		err = impl.SaveHistoryOfBaseTemplate(userId, pipeline, materials)
		if err != nil {
			return err
		}
	} else {
		CiTemplateBean := impl.CreateCiTemplateBean(request.CiPipeline.Id, request.CiPipeline.DockerConfigOverride.DockerRegistry, request.CiPipeline.DockerConfigOverride.DockerRepository, request.CiPipeline.DockerConfigOverride.CiBuildConfig.GitMaterialId, request.CiPipeline.DockerConfigOverride.CiBuildConfig, userId)
		err = impl.ciPipelineHistoryService.SaveHistory(pipeline, materials, &CiTemplateBean, repository4.TRIGGER_DELETE)
		if err != nil {
			impl.logger.Errorw("error in saving delete history for ci pipeline material and ci template overridden", "err", err)
		}
	}

	return err
}

func (impl CiCdPipelineOrchestratorImpl) DeleteCiPipelineAndCiEnvMappings(tx *pg.Tx, ciPipeline *pipelineConfig.CiPipeline, userId int32) error {
	err := impl.deleteCiEnvMapping(tx, ciPipeline, userId)
	if err != nil {
		impl.logger.Errorw("error in deleting ci-env mappings", "ciPipelineId", ciPipeline.Id, "err", err)
		return err
	}
	ciPipeline.Deleted = true
	ciPipeline.Active = false
	ciPipeline.UpdatedOn = time.Now()
	ciPipeline.UpdatedBy = userId
	err = impl.ciPipelineRepository.Update(ciPipeline, tx)
	if err != nil {
		impl.logger.Errorw("error in updating ci pipeline, DeleteCiPipeline", "pipelineId", ciPipeline.Id, "err", err)
		return err
	}
	return err
}

func (impl CiCdPipelineOrchestratorImpl) CreateCiTemplateBean(ciPipelineId int, dockerRegistryId string, dockerRepository string, gitMaterialId int, ciBuildConfig *bean2.CiBuildConfigBean, userId int32) bean2.CiTemplateBean {
	CiTemplateBean := bean2.CiTemplateBean{
		CiTemplate: nil,
		CiTemplateOverride: &pipelineConfig.CiTemplateOverride{
			CiPipelineId:     ciPipelineId,
			DockerRegistryId: dockerRegistryId,
			DockerRepository: dockerRepository,
			//DockerfilePath:   ciPipelineRequest.DockerConfigOverride.DockerBuildConfig.DockerfilePath,
			GitMaterialId: gitMaterialId,
			Active:        false,
			AuditLog: sql.AuditLog{
				CreatedBy: userId,
				CreatedOn: time.Now(),
				UpdatedBy: userId,
				UpdatedOn: time.Now(),
			},
		},
		CiBuildConfig: ciBuildConfig,
		UserId:        userId,
	}
	return CiTemplateBean
}

func (impl CiCdPipelineOrchestratorImpl) SaveHistoryOfBaseTemplate(userId int32, pipeline *pipelineConfig.CiPipeline, materials []*pipelineConfig.CiPipelineMaterial) error {
	CiTemplateBean := bean2.CiTemplateBean{
		CiTemplate:         nil,
		CiTemplateOverride: &pipelineConfig.CiTemplateOverride{},
		CiBuildConfig:      &bean2.CiBuildConfigBean{},
		UserId:             userId,
	}
	err := impl.ciPipelineHistoryService.SaveHistory(pipeline, materials, &CiTemplateBean, repository4.TRIGGER_DELETE)
	if err != nil {
		impl.logger.Errorw("error in saving delete history for ci pipeline material and ci template overridden", "err", err)
	}
	return err
}

func (impl CiCdPipelineOrchestratorImpl) deleteCiEnvMapping(tx *pg.Tx, ciPipeline *pipelineConfig.CiPipeline, userId int32) error {
	CiEnvMappingObject, err := impl.ciPipelineRepository.FindCiEnvMappingByCiPipelineId(ciPipeline.Id)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in getting CiEnvMappingObject ", "err", err, "ciPipelineId", ciPipeline.Id)
		return err
	}

	if err == nil && CiEnvMappingObject != nil {
		CiEnvMappingObject.AuditLog = sql.AuditLog{UpdatedBy: userId, UpdatedOn: time.Now()}
		CiEnvMappingObject.Deleted = true
		err = impl.ciPipelineRepository.UpdateCiEnvMapping(CiEnvMappingObject, tx)
		if err != nil {
			impl.logger.Errorw("error in getting CiEnvMappingObject ", "err", err, "ciPipelineId", CiEnvMappingObject.CiPipelineId)
			return err
		}
	}
	return nil
}
func (impl CiCdPipelineOrchestratorImpl) CreateCiConf(createRequest *bean.CiConfigRequest, templateId int) (*bean.CiConfigRequest, error) {
	//save pipeline in db start
	for _, ciPipeline := range createRequest.CiPipelines {
		argByte, err := json.Marshal(ciPipeline.DockerArgs)
		if err != nil {
			impl.logger.Errorw("err", "err", err)
			return nil, err
		}

		dbConnection := impl.pipelineRepository.GetConnection()
		tx, err := dbConnection.Begin()
		if err != nil {
			return nil, err
		}
		// Rollback tx on error.
		defer tx.Rollback()
		ciPipelineObject := &pipelineConfig.CiPipeline{
			AppId:                    createRequest.AppId,
			IsManual:                 ciPipeline.IsManual,
			IsExternal:               ciPipeline.IsExternal,
			CiTemplateId:             templateId,
			Version:                  ciPipeline.Version,
			Name:                     ciPipeline.Name,
			ParentCiPipeline:         ciPipeline.ParentCiPipeline,
			DockerArgs:               string(argByte),
			Active:                   true,
			Deleted:                  false,
			ScanEnabled:              createRequest.ScanEnabled,
			IsDockerConfigOverridden: ciPipeline.IsDockerConfigOverridden,
			PipelineType:             string(ciPipeline.PipelineType),
			AuditLog:                 sql.AuditLog{UpdatedBy: createRequest.UserId, CreatedBy: createRequest.UserId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
		}
		err = impl.ciPipelineRepository.Save(ciPipelineObject, tx)
		ciPipeline.Id = ciPipelineObject.Id
		if err != nil {
			impl.logger.Errorw("error in saving pipeline", "ciPipelineObject", ciPipelineObject, "err", err)
			return nil, err
		}

		//If customTagObejct has been passed, save it
		if !ciPipeline.EnableCustomTag {
			err := impl.customTagService.DisableCustomTagIfExist(apiBean.CustomTag{
				EntityKey:   pipelineConfigBean.EntityTypeCiPipelineId,
				EntityValue: strconv.Itoa(ciPipeline.Id),
			})
			if err != nil {
				return nil, err
			}
		} else if ciPipeline.CustomTagObject != nil && len(ciPipeline.CustomTagObject.TagPattern) != 0 {
			customTag := &apiBean.CustomTag{
				EntityKey:            pipelineConfigBean.EntityTypeCiPipelineId,
				EntityValue:          strconv.Itoa(ciPipeline.Id),
				TagPattern:           ciPipeline.CustomTagObject.TagPattern,
				AutoIncreasingNumber: ciPipeline.CustomTagObject.CounterX,
				Enabled:              ciPipeline.EnableCustomTag,
			}
			err := impl.customTagService.CreateOrUpdateCustomTag(customTag)
			if err != nil {
				return nil, err
			}
		}

		if createRequest.IsJob {
			CiEnvMapping := &pipelineConfig.CiEnvMapping{
				CiPipelineId:  ciPipeline.Id,
				EnvironmentId: ciPipeline.EnvironmentId,
				AuditLog:      sql.AuditLog{UpdatedBy: createRequest.UserId, CreatedBy: createRequest.UserId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
			}
			err = impl.ciPipelineRepository.SaveCiEnvMapping(CiEnvMapping, tx)
			if err != nil {
				impl.logger.Errorw("error in saving pipeline", "CiEnvMapping", CiEnvMapping, "err", err)
				return nil, err
			}

			if ciPipeline.EnvironmentId != 0 && !createRequest.IsCloneJob {
				createJobEnvOverrideRequest := &pipelineConfigBean.CreateJobEnvOverridePayload{
					AppId:  createRequest.AppId,
					EnvId:  ciPipeline.EnvironmentId,
					UserId: createRequest.UserId,
				}
				_, err = impl.configMapService.ConfigSecretEnvironmentCreate(createJobEnvOverrideRequest)
				if err != nil && !strings.Contains(err.Error(), "already exists") {
					impl.logger.Errorw("error in saving env override", "createJobEnvOverrideRequest", createJobEnvOverrideRequest, "err", err)
					return nil, err
				}

			}
		}

		var pipelineMaterials []*pipelineConfig.CiPipelineMaterial
		for _, r := range ciPipeline.CiMaterial {
			if ciPipeline.PipelineType == buildCommonBean.LINKED_CD {
				continue
			}
			material := &pipelineConfig.CiPipelineMaterial{
				GitMaterialId: r.GitMaterialId,
				ScmId:         r.ScmId,
				ScmVersion:    r.ScmVersion,
				ScmName:       r.ScmName,
				Value:         r.Source.Value,
				Type:          r.Source.Type,
				Path:          r.Path,
				CheckoutPath:  r.CheckoutPath,
				CiPipelineId:  ciPipelineObject.Id,
				Active:        true,
				Regex:         r.Source.Regex,
				AuditLog:      sql.AuditLog{UpdatedBy: createRequest.UserId, CreatedBy: createRequest.UserId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
			}
			if material.Regex == "" && r.Source.Type == constants2.SOURCE_TYPE_BRANCH_REGEX {
				material.Regex = r.Source.Value
			}
			pipelineMaterials = append(pipelineMaterials, material)
		}
		if len(pipelineMaterials) != 0 {
			err = impl.ciPipelineMaterialRepository.Save(tx, pipelineMaterials...)
		}
		if err != nil {
			impl.logger.Errorf("error in saving pipelineMaterials in db", "materials", pipelineMaterials, "err", err)
			return nil, err
		}
		pmIds := make(map[string]int)
		for _, pm := range pipelineMaterials {
			key := fmt.Sprintf("%d-%d", pm.CiPipelineId, pm.GitMaterialId)
			pmIds[key] = pm.Id
		}
		for _, r := range ciPipeline.CiMaterial {
			key := fmt.Sprintf("%d-%d", ciPipelineObject.Id, r.GitMaterialId)
			r.Id = pmIds[key]
		}
		if ciPipeline.IsExternal {

		} else {
			//save pipeline in db end
			if len(pipelineMaterials) != 0 {
				err = impl.AddPipelineMaterialInGitSensor(pipelineMaterials)
			}
			if err != nil {
				impl.logger.Errorf("error in saving pipelineMaterials in git sensor", "materials", pipelineMaterials, "err", err)
				return nil, err
			}
		}

		//adding ci pipeline to workflow
		appWorkflowModel, err := impl.appWorkflowRepository.FindByIdAndAppId(createRequest.AppWorkflowId, createRequest.AppId)
		if err != nil && pg.ErrNoRows != err {
			return createRequest, err
		}

		if appWorkflowModel.Id > 0 {
			appWorkflowMap := &appWorkflow.AppWorkflowMapping{
				AppWorkflowId: appWorkflowModel.Id,
				ParentId:      0,
				ComponentId:   ciPipeline.Id,
				Type:          "CI_PIPELINE",
				Active:        true,
				ParentType:    "",
				AuditLog:      sql.AuditLog{CreatedBy: createRequest.UserId, CreatedOn: time.Now(), UpdatedOn: time.Now(), UpdatedBy: createRequest.UserId},
			}
			_, err = impl.appWorkflowRepository.SaveAppWorkflowMapping(appWorkflowMap, tx)
			if err != nil {
				return createRequest, err
			}
			createRequest.AppWorkflowMapping = appWorkflowMap
		}
		err = tx.Commit()
		if err != nil {
			return nil, err
		}
		// to copy artifacts in certain cases
		if createRequest.Artifact != nil {
			createRequest.Artifact.PipelineId = ciPipeline.Id
			_, err := impl.CiArtifactRepository.SaveAll([]*repository.CiArtifact{createRequest.Artifact})
			if err != nil {
				impl.logger.Errorw("error in saving artifacts for CI pipeline", "artifact", createRequest, "err", err)
				return nil, err
			}
		}

		ciTemplateBean := &bean2.CiTemplateBean{}
		if ciPipeline.IsDockerConfigOverridden {
			//creating template override
			templateOverride := &pipelineConfig.CiTemplateOverride{
				CiPipelineId:     ciPipeline.Id,
				DockerRegistryId: ciPipeline.DockerConfigOverride.DockerRegistry,
				DockerRepository: ciPipeline.DockerConfigOverride.DockerRepository,
				//DockerfilePath:   ciPipelineRequest.DockerConfigOverride.DockerBuildConfig.DockerfilePath,
				GitMaterialId:             ciPipeline.DockerConfigOverride.CiBuildConfig.GitMaterialId,
				BuildContextGitMaterialId: ciPipeline.DockerConfigOverride.CiBuildConfig.BuildContextGitMaterialId,
				Active:                    true,
				AuditLog: sql.AuditLog{
					CreatedBy: createRequest.UserId,
					CreatedOn: time.Now(),
					UpdatedBy: createRequest.UserId,
					UpdatedOn: time.Now(),
				},
			}
			ciTemplateBean = &bean2.CiTemplateBean{
				CiTemplateOverride: templateOverride,
				CiBuildConfig:      ciPipeline.DockerConfigOverride.CiBuildConfig,
				UserId:             createRequest.UserId,
			}
			if !ciPipeline.IsExternal { //pipeline is not [linked, webhook] and overridden, then create template override
				err = impl.createDockerRepoIfNeeded(ciPipeline.DockerConfigOverride.DockerRegistry, ciPipeline.DockerConfigOverride.DockerRepository)
				// silently ignoring the error, since we don't want to fail the pipeline creation
				if err != nil {
					impl.logger.Warnw("error, createDockerRepoIfNeeded", "err", err, "dockerRegistryId", ciPipeline.DockerConfigOverride.DockerRegistry, "dockerRegistry", ciPipeline.DockerConfigOverride.DockerRepository)
				}
				err := impl.ciTemplateService.Save(ciTemplateBean)
				if err != nil {
					return nil, err
				}
			}
		}
		err = impl.ciPipelineHistoryService.SaveHistory(ciPipelineObject, pipelineMaterials, ciTemplateBean, repository4.TRIGGER_ADD)
		if err != nil {
			impl.logger.Errorw("error in saving history for ci pipeline", "err", err, "ciPipelineId", ciPipelineObject.Id)
		}

		//creating ci stages after tx commit due to FK constraints
		if ciPipeline.PreBuildStage != nil && len(ciPipeline.PreBuildStage.Steps) > 0 {
			//creating pre stage
			err = impl.pipelineStageService.CreatePipelineStage(ciPipeline.PreBuildStage, repository5.PIPELINE_STAGE_TYPE_PRE_CI, ciPipeline.Id, createRequest.UserId)
			if err != nil {
				impl.logger.Errorw("error in creating pre stage", "err", err, "preBuildStage", ciPipeline.PreBuildStage, "ciPipelineId", ciPipeline.Id)
				return nil, err
			}
		}
		if ciPipeline.PostBuildStage != nil && len(ciPipeline.PostBuildStage.Steps) > 0 {
			//creating post stage
			err = impl.pipelineStageService.CreatePipelineStage(ciPipeline.PostBuildStage, repository5.PIPELINE_STAGE_TYPE_POST_CI, ciPipeline.Id, createRequest.UserId)
			if err != nil {
				impl.logger.Errorw("error in creating post stage", "err", err, "postBuildStage", ciPipeline.PostBuildStage, "ciPipelineId", ciPipeline.Id)
				return nil, err
			}
		}
		for _, r := range ciPipeline.CiMaterial {
			ciMaterial, err := impl.ciPipelineMaterialRepository.GetById(r.Id)
			if err != nil && pg.ErrNoRows != err {
				return nil, err
			}
			if ciMaterial != nil && ciMaterial.GitMaterial != nil {
				r.GitMaterialName = ciMaterial.GitMaterial.Name[strings.Index(ciMaterial.GitMaterial.Name, "-")+1:]
			}
		}
	}
	return createRequest, nil
}

func (impl CiCdPipelineOrchestratorImpl) BuildCiPipelineScript(userId int32, ciScript *bean.CiScript, scriptStage string, ciPipeline *bean.CiPipeline) *pipelineConfig.CiPipelineScript {
	ciPipelineScript := &pipelineConfig.CiPipelineScript{
		Name:           ciScript.Name,
		Index:          ciScript.Index,
		CiPipelineId:   ciPipeline.Id,
		Script:         ciScript.Script,
		Stage:          scriptStage,
		Active:         true,
		OutputLocation: ciScript.OutputLocation,
		AuditLog: sql.AuditLog{
			CreatedOn: time.Now(),
			CreatedBy: userId,
			UpdatedOn: time.Now(),
			UpdatedBy: userId,
		},
	}
	if ciScript.Id != 0 {
		ciPipelineScript.Id = ciScript.Id
	}
	return ciPipelineScript
}

func (impl CiCdPipelineOrchestratorImpl) generateApiKey(ciPipelineId int, ciPipelineName string, secret string) (prefix, sha string) {
	hashData := strconv.Itoa(ciPipelineId) + "-" + ciPipelineName + "-" + time.Now().String()
	prefix = base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(ciPipelineId)))
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(hashData))
	if err != nil {
		impl.logger.Error(err)
	}
	sha = hex.EncodeToString(h.Sum(nil))
	return prefix, sha
}

func (impl CiCdPipelineOrchestratorImpl) generateExternalCiPayload(ciPipeline *bean.CiPipeline, externalCiPipeline *pipelineConfig.ExternalCiPipeline, keyPrefix string, apiKey string) *bean.CiPipeline {
	if impl.ciConfig.ExternalCiWebhookUrl == "" {
		hostUrl, err := impl.attributesService.GetByKey(attributesBean.HostUrlKey)
		if err != nil {
			impl.logger.Errorw("there is no external ci webhook url configured", "ci pipeline", ciPipeline)
			return nil
		}
		if hostUrl != nil {
			impl.ciConfig.ExternalCiWebhookUrl = fmt.Sprintf("%s/%s", hostUrl.Value, types.ExternalCiWebhookPath)
		}
	}
	accessKey := keyPrefix + "." + apiKey
	ciPipeline.ExternalCiConfig = bean.ExternalCiConfig{
		WebhookUrl: impl.ciConfig.ExternalCiWebhookUrl,
		AccessKey:  accessKey,
		Payload:    impl.ciConfig.ExternalCiPayload,
	}
	return ciPipeline
}

func (impl CiCdPipelineOrchestratorImpl) AddPipelineMaterialInGitSensor(pipelineMaterials []*pipelineConfig.CiPipelineMaterial) error {
	var materials []*gitSensor.CiPipelineMaterial
	for _, ciPipelineMaterial := range pipelineMaterials {
		if ciPipelineMaterial.Type != constants2.SOURCE_TYPE_BRANCH_REGEX {
			material := &gitSensor.CiPipelineMaterial{
				Id:            ciPipelineMaterial.Id,
				Active:        ciPipelineMaterial.Active,
				Value:         ciPipelineMaterial.Value,
				GitMaterialId: ciPipelineMaterial.GitMaterialId,
				Type:          gitSensor.SourceType(ciPipelineMaterial.Type),
			}
			materials = append(materials, material)
		}
	}

	return impl.GitSensorClient.SavePipelineMaterial(context.Background(), materials)
}

func (impl CiCdPipelineOrchestratorImpl) CheckStringMatchRegex(regex string, value string) bool {
	response, err := regexp.MatchString(regex, value)
	if err != nil {
		return false
	}
	return response
}

func (impl CiCdPipelineOrchestratorImpl) CreateApp(createRequest *bean.CreateAppDTO) (*bean.CreateAppDTO, error) {
	// validate the labels key-value if propagate is true
	for _, label := range createRequest.AppLabels {
		if !label.Propagate {
			continue
		}
		labelKey := label.Key
		labelValue := label.Value
		err := util3.CheckIfValidLabel(labelKey, labelValue)
		if err != nil {
			return nil, err
		}
	}

	dbConnection := impl.appRepository.GetConnection()
	tx, err := dbConnection.Begin()
	if err != nil {
		return nil, err
	}
	// Rollback tx on error.
	defer tx.Rollback()
	app, err := impl.createAppGroup(createRequest.AppName, createRequest.Description, createRequest.UserId, createRequest.TeamId, createRequest.AppType, tx)
	if err != nil {
		return nil, err
	}
	err = impl.storeGenericNote(tx, createRequest, app.Id)
	if err != nil {
		impl.logger.Errorw("error in saving generic note", "err", err, "genericNoteObj", createRequest.GenericNote, "userId", createRequest.UserId)
		return nil, err
	}
	// create labels and tags with app
	if app.Active && len(createRequest.AppLabels) > 0 {
		appLabelMap := make(map[string]bool)
		for _, label := range createRequest.AppLabels {
			uniqueLabelExists := fmt.Sprintf("%s:%s:%t", label.Key, label.Value, label.Propagate)
			if _, ok := appLabelMap[uniqueLabelExists]; !ok {
				appLabelMap[uniqueLabelExists] = true
				request := &bean.AppLabelDto{
					AppId:     app.Id,
					Key:       label.Key,
					Value:     label.Value,
					Propagate: label.Propagate,
					UserId:    createRequest.UserId,
				}
				_, err := impl.appLabelsService.Create(request, tx)
				if err != nil {
					impl.logger.Errorw("error on creating labels for app id ", "err", err, "appId", app.Id)
					return nil, err
				}
			}
		}
	}
	err = tx.Commit()
	if err != nil {
		impl.logger.Errorw("error in commit repo", "error", err)
		return nil, err
	}
	createRequest.Id = app.Id
	if createRequest.AppType == helper.Job {
		createRequest.AppName = app.DisplayName
	}
	return createRequest, nil
}

func (impl CiCdPipelineOrchestratorImpl) storeGenericNote(tx *pg.Tx, createRequest *bean.CreateAppDTO, appId int) error {
	if createRequest.GenericNote != nil && createRequest.GenericNote.Description != "" {
		genericNoteObj := repository3.GenericNote{
			Description:    createRequest.GenericNote.Description,
			IdentifierType: repository3.AppType,
			Identifier:     appId,
		}
		note, err := impl.genericNoteService.Save(tx, &genericNoteObj, createRequest.UserId)
		if err != nil {
			impl.logger.Errorw("error in saving description", "err", err, "genericNoteObj", genericNoteObj, "userId", createRequest.UserId)
			return err
		}
		createRequest.GenericNote = note
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) DeleteApp(appId int, userId int32) error {
	// Delete git materials,call git sensor and delete app
	impl.logger.Debug("deleting materials in orchestrator")
	materials, err := impl.materialRepository.FindByAppId(appId)
	if err != nil && !util.IsErrNoRows(err) {
		impl.logger.Errorw("err", err)
		return err
	}
	for i := range materials {
		materials[i].Active = false
		materials[i].UpdatedOn = time.Now()
		materials[i].UpdatedBy = userId
	}
	err = impl.materialRepository.Update(materials)

	if err != nil {
		impl.logger.Errorw("could not delete materials ", "err", err)
		return err
	}

	err = impl.gitMaterialHistoryService.CreateDeleteMaterialHistory(materials)

	impl.logger.Debug("deleting materials in git_sensor")
	for _, m := range materials {
		err = impl.updateRepositoryToGitSensor(m, "", false)
		if err != nil {
			impl.logger.Errorw("error in updating to git-sensor", "err", err)
			return err
		}
	}

	app, err := impl.appRepository.FindById(appId)
	if err != nil {
		impl.logger.Errorw("err", err)
		return err
	}
	dbConnection := impl.appRepository.GetConnection()
	tx, err := dbConnection.Begin()
	if err != nil {
		impl.logger.Errorw("error in establishing connection", "err", err)
		return err
	}
	// Rollback tx on error.
	defer tx.Rollback()
	// deleting deployment config first as it is dependent on app
	appDeploymentConfig, err := impl.deploymentConfigService.GetAndMigrateConfigIfAbsentForDevtronApps(appId, 0)
	if err != nil && !errors.Is(err, pg.ErrNoRows) {
		impl.logger.Errorw("error in fetching environment deployment config by appId and envId", "appId", appId, "err", err)
		return err
	} else if err == nil && appDeploymentConfig != nil {
		appDeploymentConfig.Active = false
		appDeploymentConfig, err = impl.deploymentConfigService.CreateOrUpdateConfig(tx, appDeploymentConfig, userId)
		if err != nil {
			impl.logger.Errorw("error in deleting deployment config for pipeline", "appId", appId, "err", err)
			return err
		}
	}
	// deleting app
	app.Active = false
	app.UpdatedOn = time.Now()
	app.UpdatedBy = userId
	err = impl.appRepository.UpdateWithTxn(app, tx)
	if err != nil {
		impl.logger.Errorw("err", "err", err)
		return err
	}
	//deleting auth roles entries for this project
	err = impl.userAuthService.DeleteRoles(bean3.APP_TYPE, app.AppName, tx, "", "")
	if err != nil {
		impl.logger.Errorw("error in deleting auth roles", "err", err)
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) CreateMaterials(createMaterialRequest *bean.CreateMaterialDTO) (*bean.CreateMaterialDTO, error) {
	tx, err := impl.transactionManager.StartTx()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	existingMaterials, err := impl.materialRepository.FindByAppId(createMaterialRequest.AppId)
	if err != nil {
		impl.logger.Errorw("err", "err", err)
		return nil, err
	}
	checkoutPaths := make(map[int]string)
	impl.logger.Debugw("existing materials", "material", existingMaterials)
	for _, material := range existingMaterials {
		checkoutPaths[material.Id] = material.CheckoutPath
	}
	for i, material := range createMaterialRequest.Material {
		if material.CheckoutPath == "" {
			material.CheckoutPath = "./"
		}
		checkoutPaths[i*-1] = material.CheckoutPath
	}
	duplicatePathErr := impl.validateCheckoutPathsForMultiGit(checkoutPaths)
	if duplicatePathErr != nil {
		impl.logger.Errorw("duplicate checkout paths", "err", err)
		return nil, duplicatePathErr
	}
	var materials []*bean.GitMaterial
	for _, inputMaterial := range createMaterialRequest.Material {
		inputMaterial.UpdateSanitisedGitRepoUrl()
		m, err := impl.createMaterial(tx, inputMaterial, createMaterialRequest.AppId, createMaterialRequest.UserId)
		inputMaterial.Id = m.Id
		if err != nil {
			return nil, err
		}
		materials = append(materials, inputMaterial)
	}
	// moving transaction before addRepositoryToGitSensor as commiting transaction after addRepositoryToGitSensor was causing problems
	// in case request was cancelled data was getting saved in git sensor but not getting saved in orchestrator db. Same is done in update flow.
	err = impl.transactionManager.CommitTx(tx)
	if err != nil {
		impl.logger.Errorw("error in committing tx Create material", "err", err, "materials", materials)
		return nil, err
	}
	err = impl.addRepositoryToGitSensor(materials, "")
	if err != nil {
		impl.logger.Errorw("error in updating to sensor", "err", err)
		return nil, err
	}
	impl.logger.Debugw("all materials are ", "materials", materials)
	return createMaterialRequest, nil
}

func (impl CiCdPipelineOrchestratorImpl) UpdateMaterial(updateMaterialDTO *bean.UpdateMaterialDTO) (*bean.UpdateMaterialDTO, error) {
	tx, err := impl.transactionManager.StartTx()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	updatedMaterial, err := impl.updateMaterial(tx, updateMaterialDTO)
	if err != nil {
		impl.logger.Errorw("err", "err", err)
		return nil, err
	}
	err = impl.transactionManager.CommitTx(tx)
	if err != nil {
		impl.logger.Errorw("error in committing tx Create material", "err", err)
		return nil, err
	}

	err = impl.updateRepositoryToGitSensor(updatedMaterial, "",
		updateMaterialDTO.Material.CreateBackup)
	if err != nil {
		impl.logger.Errorw("error in updating to git-sensor", "err", err)
		return nil, err
	}
	return updateMaterialDTO, nil
}

func (impl CiCdPipelineOrchestratorImpl) updateRepositoryToGitSensor(material *repository6.GitMaterial,
	cloningMode string, createBackup bool) error {
	sensorMaterial := &gitSensor.GitMaterial{
		Name:             material.Name,
		Url:              material.Url,
		Id:               material.Id,
		GitProviderId:    material.GitProviderId,
		CheckoutLocation: material.CheckoutPath,
		Deleted:          !material.Active,
		FetchSubmodules:  material.FetchSubmodules,
		FilterPattern:    material.FilterPattern,
		CloningMode:      cloningMode,
		CreateBackup:     createBackup,
	}
	timeout := 10 * time.Minute
	if createBackup {
		// additional time may be required for dir snapshot
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return impl.GitSensorClient.UpdateRepo(ctx, sensorMaterial)
}

func (impl CiCdPipelineOrchestratorImpl) addRepositoryToGitSensor(materials []*bean.GitMaterial, cloningMode string) error {
	var sensorMaterials []*gitSensor.GitMaterial
	for _, material := range materials {
		sensorMaterial := &gitSensor.GitMaterial{
			Name:            material.Name,
			Url:             material.Url,
			Id:              material.Id,
			GitProviderId:   material.GitProviderId,
			Deleted:         false,
			FetchSubmodules: material.FetchSubmodules,
			FilterPattern:   material.FilterPattern,
			CloningMode:     cloningMode,
		}
		sensorMaterials = append(sensorMaterials, sensorMaterial)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return impl.GitSensorClient.AddRepo(ctx, sensorMaterials)
}

// FIXME: not thread safe
func (impl CiCdPipelineOrchestratorImpl) createAppGroup(name, description string, userId int32, teamId int, appType helper.AppType, tx *pg.Tx) (*app2.App, error) {
	app, err := impl.appRepository.FindActiveByName(name)
	if err != nil && err != pg.ErrNoRows {
		return nil, err
	}
	if appType != helper.Job {
		if app != nil && app.Id > 0 {
			impl.logger.Warnw("app already exists", "name", name)
			err = &util.ApiError{
				Code:            constants.AppAlreadyExists.Code,
				InternalMessage: "app already exists",
				UserMessage:     constants.AppAlreadyExists.UserMessage(name),
			}
			return nil, err
		}
	} else {
		job, err := impl.appRepository.FindJobByDisplayName(name)
		if err != nil && err != pg.ErrNoRows {
			return nil, err
		}
		if job != nil && job.Id > 0 {
			impl.logger.Warnw("job already exists", "name", name)
			err = &util.ApiError{
				Code:            constants.AppAlreadyExists.Code,
				InternalMessage: "job already exists",
				UserMessage:     constants.AppAlreadyExists.UserMessage(name),
			}
			return nil, err
		}
	}

	displayName := name
	appName := name
	if appType == helper.Job {
		appName = name + "-" + util2.Generate(8) + "J" + bean2.UniquePlaceHolderForAppName
	}
	pg := &app2.App{
		Active:      true,
		AppName:     appName,
		DisplayName: displayName,
		Description: description,
		TeamId:      teamId,
		AppType:     appType,
		AuditLog:    sql.AuditLog{UpdatedBy: userId, CreatedBy: userId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
	}
	err = impl.appRepository.SaveWithTxn(pg, tx)
	if err != nil {
		impl.logger.Errorw("error in saving entity ", "entity", pg)
		return nil, err
	}

	apps, err := impl.appRepository.FindActiveListByName(name)
	if err != nil {
		return nil, err
	}
	appLen := len(apps)
	if appLen > 1 {
		firstElement := apps[0]
		if firstElement.Id != pg.Id {
			pg.Active = false
			err = impl.appRepository.UpdateWithTxn(pg, tx)
			if err != nil {
				impl.logger.Errorw("error in saving entity ", "entity", pg)
				return nil, err
			}
			err = &util.ApiError{
				Code:            constants.AppAlreadyExists.Code,
				InternalMessage: "app already exists",
				UserMessage:     constants.AppAlreadyExists.UserMessage(name),
			}
			return nil, err
		}
	}
	return pg, nil
}

func (impl CiCdPipelineOrchestratorImpl) validateCheckoutPathsForMultiGit(allPaths map[int]string) error {
	dockerfilePathMap := make(map[string]bool)
	impl.logger.Debugw("all paths ", "path", allPaths)
	isMulti := len(allPaths) > 1
	for _, c := range allPaths {
		if isMulti && (c == "") {
			impl.logger.Errorw("validation err", "err", "checkout path required for multi-git")
			return fmt.Errorf("checkout path required for multi-git")
		}
		if !strings.HasPrefix(c, "./") {
			impl.logger.Errorw("validation err", "err", "invalid checkout path it must start with ./")
			return fmt.Errorf("invalid checkout path it must start with ./ ")
		}
		if _, ok := dockerfilePathMap[c]; ok {
			impl.logger.Error("duplicate checkout paths found")
			return errors.New("duplicate checkout paths found")
		}
		dockerfilePathMap[c] = true
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) updateMaterial(tx *pg.Tx, updateMaterialDTO *bean.UpdateMaterialDTO) (*repository6.GitMaterial, error) {
	existingMaterials, err := impl.materialRepository.FindByAppId(updateMaterialDTO.AppId)
	if err != nil {
		impl.logger.Errorw("err", "err", err)
		return nil, err
	}
	checkoutPaths := make(map[int]string)
	for _, material := range existingMaterials {
		checkoutPaths[material.Id] = material.CheckoutPath
	}
	var currentMaterial *repository6.GitMaterial
	for _, m := range existingMaterials {
		if m.Id == updateMaterialDTO.Material.Id {
			currentMaterial = m
			break
		}
	}
	if currentMaterial == nil {
		return nil, errors.New("material to be updated does not exist")
	}
	if updateMaterialDTO.Material.CheckoutPath == "" {
		updateMaterialDTO.Material.CheckoutPath = "./"
	}
	checkoutPaths[updateMaterialDTO.Material.Id] = updateMaterialDTO.Material.CheckoutPath
	validationErr := impl.validateCheckoutPathsForMultiGit(checkoutPaths)
	if validationErr != nil {
		impl.logger.Errorw("validation err", "err", err)
		return nil, validationErr
	}
	updateMaterialDTO.Material.UpdateSanitisedGitRepoUrl()
	currentMaterial.Url = updateMaterialDTO.Material.Url
	basePath := path.Base(updateMaterialDTO.Material.Url)
	basePath = strings.TrimSuffix(basePath, ".git")

	currentMaterial.Name = strconv.Itoa(updateMaterialDTO.Material.GitProviderId) + "-" + basePath
	currentMaterial.GitProviderId = updateMaterialDTO.Material.GitProviderId
	currentMaterial.CheckoutPath = updateMaterialDTO.Material.CheckoutPath
	currentMaterial.FetchSubmodules = updateMaterialDTO.Material.FetchSubmodules
	currentMaterial.FilterPattern = updateMaterialDTO.Material.FilterPattern
	currentMaterial.AuditLog = sql.AuditLog{UpdatedBy: updateMaterialDTO.UserId, CreatedBy: currentMaterial.CreatedBy, UpdatedOn: time.Now(), CreatedOn: currentMaterial.CreatedOn}

	err = impl.materialRepository.UpdateMaterial(tx, currentMaterial)

	if err != nil {
		impl.logger.Errorw("error in updating material", "material", currentMaterial, "err", err)
		return nil, err
	}

	err = impl.gitMaterialHistoryService.CreateMaterialHistory(tx, currentMaterial)

	return currentMaterial, nil
}

func (impl CiCdPipelineOrchestratorImpl) createMaterial(tx *pg.Tx, inputMaterial *bean.GitMaterial, appId int, userId int32) (*repository6.GitMaterial, error) {
	basePath := path.Base(inputMaterial.Url)
	basePath = strings.TrimSuffix(basePath, ".git")
	material := &repository6.GitMaterial{
		Url:             inputMaterial.Url,
		AppId:           appId,
		Name:            strconv.Itoa(inputMaterial.GitProviderId) + "-" + basePath,
		GitProviderId:   inputMaterial.GitProviderId,
		Active:          true,
		CheckoutPath:    inputMaterial.CheckoutPath,
		FetchSubmodules: inputMaterial.FetchSubmodules,
		FilterPattern:   inputMaterial.FilterPattern,
		AuditLog:        sql.AuditLog{UpdatedBy: userId, CreatedBy: userId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
	}
	err := impl.materialRepository.SaveMaterial(tx, material)
	if err != nil {
		impl.logger.Errorw("error in saving material", "material", material, "err", err)
		return nil, err
	}
	err = impl.gitMaterialHistoryService.CreateMaterialHistory(tx, material)
	return material, err
}

func (impl CiCdPipelineOrchestratorImpl) CreateCDPipelines(pipelineRequest *bean.CDPipelineConfigObject, appId int, userId int32, tx *pg.Tx, appName string) (pipelineId int, err error) {
	preStageConfig := ""
	preTriggerType := pipelineConfig.TriggerType("")
	if len(pipelineRequest.PreStage.Config) > 0 {
		preStageConfig = pipelineRequest.PreStage.Config
		preTriggerType = pipelineRequest.PreStage.TriggerType
	}

	if pipelineRequest.PreDeployStage != nil {
		preTriggerType = pipelineRequest.PreDeployStage.TriggerType
	}

	postStageConfig := ""
	postTriggerType := pipelineConfig.TriggerType("")
	if len(pipelineRequest.PostStage.Config) > 0 {
		postStageConfig = pipelineRequest.PostStage.Config
		postTriggerType = pipelineRequest.PostStage.TriggerType
	}

	if pipelineRequest.PostDeployStage != nil {
		postTriggerType = pipelineRequest.PostDeployStage.TriggerType
	}

	preStageConfigMapSecretNames, err := json.Marshal(&pipelineRequest.PreStageConfigMapSecretNames)
	if err != nil {
		impl.logger.Error(err)
		return 0, err
	}

	postStageConfigMapSecretNames, err := json.Marshal(&pipelineRequest.PostStageConfigMapSecretNames)
	if err != nil {
		impl.logger.Error(err)
		return 0, err
	}

	env, err := impl.envRepository.FindById(pipelineRequest.EnvironmentId)
	if err != nil {
		impl.logger.Errorw("error in getting environment by id", "err", err)
		return 0, err
	}
	pipeline := &pipelineConfig.Pipeline{
		EnvironmentId:                 pipelineRequest.EnvironmentId,
		AppId:                         appId,
		Name:                          pipelineRequest.Name,
		Deleted:                       false,
		CiPipelineId:                  pipelineRequest.CiPipelineId,
		TriggerType:                   pipelineRequest.TriggerType,
		PreStageConfig:                preStageConfig,
		PostStageConfig:               postStageConfig,
		PreTriggerType:                preTriggerType,
		PostTriggerType:               postTriggerType,
		PreStageConfigMapSecretNames:  string(preStageConfigMapSecretNames),
		PostStageConfigMapSecretNames: string(postStageConfigMapSecretNames),
		RunPreStageInEnv:              pipelineRequest.RunPreStageInEnv,
		RunPostStageInEnv:             pipelineRequest.RunPostStageInEnv,
		DeploymentAppCreated:          false,
		DeploymentAppType:             pipelineRequest.DeploymentAppType,
		DeploymentAppName:             fmt.Sprintf("%s-%s", appName, env.Name),
		AuditLog:                      sql.AuditLog{UpdatedBy: userId, CreatedBy: userId, UpdatedOn: time.Now(), CreatedOn: time.Now()},
	}

	if pipelineRequest.IsLinkedRelease() {
		if len(pipelineRequest.DeploymentAppName) == 0 {
			return 0, util.DefaultApiError().
				WithHttpStatusCode(http.StatusUnprocessableEntity).
				WithInternalMessage("deploymentAppName is required for releaseMode: link").
				WithUserMessage("deploymentAppName is required for releaseMode: link")
		}
		//Here we are linking an external helm release so deployment_app_name = <external-release-name> and deployment_app_created = true as release already exist
		// external release name is sent from FE in pipelineRequest.DeploymentAppName field
		pipeline.DeploymentAppName = pipelineRequest.DeploymentAppName
		pipeline.DeploymentAppCreated = true
	}
	if len(pipeline.DeploymentAppName) == 0 {
		pipeline.DeploymentAppName = util2.BuildDeployedAppName(appName, env.Name)
	}

	err = impl.pipelineRepository.Save([]*pipelineConfig.Pipeline{pipeline}, tx)
	if err != nil {
		impl.logger.Errorw("error in saving cd pipeline", "err", err, "pipeline", pipeline)
		return 0, err
	}
	if pipeline.PreStageConfig != "" {
		err = impl.prePostCdScriptHistoryService.CreatePrePostCdScriptHistory(pipeline, tx, repository4.PRE_CD_TYPE, false, 0, time.Time{})
		if err != nil {
			impl.logger.Errorw("error in creating pre cd script entry", "err", err, "pipeline", pipeline)
			return 0, err
		}
	}
	if pipeline.PostStageConfig != "" {
		err = impl.prePostCdScriptHistoryService.CreatePrePostCdScriptHistory(pipeline, tx, repository4.POST_CD_TYPE, false, 0, time.Time{})
		if err != nil {
			impl.logger.Errorw("error in creating post cd script entry", "err", err, "pipeline", pipeline)
			return 0, err
		}
	}
	return pipeline.Id, nil
}

func (impl CiCdPipelineOrchestratorImpl) UpdateCDPipeline(pipelineRequest *bean.CDPipelineConfigObject, userId int32, tx *pg.Tx) (pipeline *pipelineConfig.Pipeline, err error) {
	pipeline, err = impl.pipelineRepository.FindById(pipelineRequest.Id)
	if err == pg.ErrNoRows {
		return pipeline, fmt.Errorf("no cd pipeline found")
	} else if err != nil {
		return pipeline, err
	} else if pipeline.Id == 0 {
		return pipeline, fmt.Errorf("no cd pipeline found")
	}
	preStageConfig := ""
	preTriggerType := pipelineConfig.TriggerType("")
	if len(pipelineRequest.PreStage.Config) > 0 {
		preStageConfig = pipelineRequest.PreStage.Config
		preTriggerType = pipelineRequest.PreStage.TriggerType
	}
	if pipelineRequest.PreDeployStage != nil {
		preTriggerType = pipelineRequest.PreDeployStage.TriggerType
	}

	postStageConfig := ""
	postTriggerType := pipelineConfig.TriggerType("")
	if len(pipelineRequest.PostStage.Config) > 0 {
		postStageConfig = pipelineRequest.PostStage.Config
		postTriggerType = pipelineRequest.PostStage.TriggerType
	}
	if pipelineRequest.PostDeployStage != nil {
		postTriggerType = pipelineRequest.PostDeployStage.TriggerType
	}

	preStageConfigMapSecretNames, err := json.Marshal(&pipelineRequest.PreStageConfigMapSecretNames)
	if err != nil {
		impl.logger.Error(err)
		return pipeline, err
	}

	postStageConfigMapSecretNames, err := json.Marshal(&pipelineRequest.PostStageConfigMapSecretNames)
	if err != nil {
		impl.logger.Error(err)
		return pipeline, err
	}

	pipeline.TriggerType = pipelineRequest.TriggerType
	pipeline.PreTriggerType = preTriggerType
	pipeline.PostTriggerType = postTriggerType
	pipeline.PreStageConfig = preStageConfig
	pipeline.PostStageConfig = postStageConfig
	pipeline.PreStageConfigMapSecretNames = string(preStageConfigMapSecretNames)
	pipeline.PostStageConfigMapSecretNames = string(postStageConfigMapSecretNames)
	pipeline.RunPreStageInEnv = pipelineRequest.RunPreStageInEnv
	pipeline.RunPostStageInEnv = pipelineRequest.RunPostStageInEnv
	pipeline.UpdatedBy = userId
	pipeline.UpdatedOn = time.Now()
	err = impl.pipelineRepository.Update(pipeline, tx)
	if err != nil {
		impl.logger.Errorw("error in updating cd pipeline", "err", err, "pipeline", pipeline)
		return pipeline, err
	}
	if pipeline.PreStageConfig != "" {
		err = impl.prePostCdScriptHistoryService.CreatePrePostCdScriptHistory(pipeline, tx, repository4.PRE_CD_TYPE, false, 0, time.Time{})
		if err != nil {
			impl.logger.Errorw("error in creating pre cd script entry", "err", err, "pipeline", pipeline)
			return pipeline, err
		}
	}
	if pipeline.PostStageConfig != "" {
		err = impl.prePostCdScriptHistoryService.CreatePrePostCdScriptHistory(pipeline, tx, repository4.POST_CD_TYPE, false, 0, time.Time{})
		if err != nil {
			impl.logger.Errorw("error in creating post cd script entry", "err", err, "pipeline", pipeline)
			return pipeline, err
		}
	}

	if pipelineRequest.PreDeployStage != nil {
		//updating pre stage
		err = impl.pipelineStageService.UpdatePipelineStage(pipelineRequest.PreDeployStage, repository5.PIPELINE_STAGE_TYPE_PRE_CD, pipelineRequest.Id, userId)
		if err != nil {
			impl.logger.Errorw("error in updating pre stage", "err", err, "preDeployStage", pipelineRequest.PreDeployStage, "cdPipelineId", pipelineRequest.Id)
			return pipeline, err
		}
	}
	if pipelineRequest.PostDeployStage != nil {
		//updating post stage
		err = impl.pipelineStageService.UpdatePipelineStage(pipelineRequest.PostDeployStage, repository5.PIPELINE_STAGE_TYPE_POST_CD, pipelineRequest.Id, userId)
		if err != nil {
			impl.logger.Errorw("error in updating post stage", "err", err, "postDeployStage", pipelineRequest.PostDeployStage, "cdPipelineId", pipelineRequest.Id)
			return pipeline, err
		}
	}
	return pipeline, nil
}

func (impl CiCdPipelineOrchestratorImpl) DeleteCdPipeline(pipelineId int, userId int32, tx *pg.Tx) error {
	return impl.pipelineRepository.Delete(pipelineId, userId, tx)
}
func (impl CiCdPipelineOrchestratorImpl) getPipelineIdAndPrePostStageMapping(dbPipelines []*pipelineConfig.Pipeline) (map[int][]*pipelineConfigBean.PipelineStageDto, error) {
	var err error
	pipelineIdAndPrePostStageMapping := make(map[int][]*pipelineConfigBean.PipelineStageDto, len(dbPipelines))
	dbPipelineIds := make([]int, 0, len(dbPipelines))
	pipelineMap := make(map[int]*pipelineConfig.Pipeline, len(dbPipelines))
	for _, pipeline := range dbPipelines {
		pipelineMap[pipeline.Id] = pipeline
		dbPipelineIds = append(dbPipelineIds, pipeline.Id)
	}
	if len(dbPipelineIds) > 0 {
		pipelineIdAndPrePostStageMapping, err = impl.pipelineStageService.GetCdPipelineStageDataDeepCopyForPipelineIds(dbPipelineIds, pipelineMap)
		if err != nil {
			impl.logger.Errorw("error in fetching pipelinePrePostStageMapping", "err", err, "cdPipelineIds", dbPipelineIds)
			return nil, err
		}
	}
	return pipelineIdAndPrePostStageMapping, nil
}

func (impl CiCdPipelineOrchestratorImpl) PipelineExists(name string) (bool, error) {
	return impl.pipelineRepository.PipelineExists(name)
}

func (impl CiCdPipelineOrchestratorImpl) GetCdPipelinesForApp(appId int) (cdPipelines *bean.CdPipelines, err error) {
	dbPipelines, err := impl.pipelineRepository.FindActiveByAppId(appId)
	if err != nil {
		impl.logger.Errorw("error in fetching cdPipeline", "appId", appId, "err", err)
	}
	pipelineIdAndPrePostStageMapping, err := impl.getPipelineIdAndPrePostStageMapping(dbPipelines)
	if err != nil {
		impl.logger.Errorw("error in fetching pipelineIdAndPrePostStageMapping", "err", err)
		return nil, err
	}

	isAppLevelGitOpsConfigured := false
	if len(dbPipelines) != 0 {
		isAppLevelGitOpsConfigured, err = impl.chartService.IsGitOpsRepoConfiguredForDevtronApp(appId)
		if err != nil {
			impl.logger.Errorw("error in fetching latest chart for app by appId")
			return nil, err
		}
	}

	var pipelines []*bean.CDPipelineConfigObject
	for _, dbPipeline := range dbPipelines {

		envDeploymentConfig, err := impl.deploymentConfigService.GetConfigForDevtronApps(dbPipeline.AppId, dbPipeline.EnvironmentId)
		if err != nil {
			impl.logger.Errorw("error in fetching environment deployment config by appId and envId", "appId", appId, "envId", dbPipeline.EnvironmentId, "err", err)
			return nil, err
		}

		preStage := bean.CdStage{}
		if len(dbPipeline.PreStageConfig) > 0 {
			preStage.Name = "Pre-Deployment"
			preStage.Config = dbPipeline.PreStageConfig
			preStage.TriggerType = dbPipeline.PreTriggerType
		}
		postStage := bean.CdStage{}
		if len(dbPipeline.PostStageConfig) > 0 {
			postStage.Name = "Post-Deployment"
			postStage.Config = dbPipeline.PostStageConfig
			postStage.TriggerType = dbPipeline.PostTriggerType
		}

		preStageConfigmapSecrets := bean.PreStageConfigMapSecretNames{}
		postStageConfigmapSecrets := bean.PostStageConfigMapSecretNames{}

		if dbPipeline.PreStageConfigMapSecretNames != "" {
			err = json.Unmarshal([]byte(dbPipeline.PreStageConfigMapSecretNames), &preStageConfigmapSecrets)
			if err != nil {
				impl.logger.Error(err)
				return nil, err
			}
		}
		if dbPipeline.PostStageConfigMapSecretNames != "" {
			err = json.Unmarshal([]byte(dbPipeline.PostStageConfigMapSecretNames), &postStageConfigmapSecrets)
			if err != nil {
				impl.logger.Error(err)
				return nil, err
			}
		}

		pipeline := &bean.CDPipelineConfigObject{
			Id:                            dbPipeline.Id,
			Name:                          dbPipeline.Name,
			EnvironmentId:                 dbPipeline.EnvironmentId,
			EnvironmentName:               dbPipeline.Environment.Name,
			Description:                   dbPipeline.Environment.Description,
			CiPipelineId:                  dbPipeline.CiPipelineId,
			TriggerType:                   dbPipeline.TriggerType,
			PreStage:                      preStage,
			PostStage:                     postStage,
			RunPreStageInEnv:              dbPipeline.RunPreStageInEnv,
			RunPostStageInEnv:             dbPipeline.RunPostStageInEnv,
			PreStageConfigMapSecretNames:  preStageConfigmapSecrets,
			PostStageConfigMapSecretNames: postStageConfigmapSecrets,
			DeploymentAppType:             envDeploymentConfig.DeploymentAppType,
			ReleaseMode:                   envDeploymentConfig.ReleaseMode,
			DeploymentAppCreated:          dbPipeline.DeploymentAppCreated,
			DeploymentAppDeleteRequest:    dbPipeline.DeploymentAppDeleteRequest,
			IsVirtualEnvironment:          dbPipeline.Environment.IsVirtualEnvironment,
			IsGitOpsRepoNotConfigured:     !envDeploymentConfig.IsPipelineGitOpsRepoConfigured(isAppLevelGitOpsConfigured),
		}
		if pipelineStages, ok := pipelineIdAndPrePostStageMapping[dbPipeline.Id]; ok {
			pipeline.PreDeployStage = pipelineStages[0]
			pipeline.PostDeployStage = pipelineStages[1]
		}
		pipelines = append(pipelines, pipeline)
	}
	cdPipelines = &bean.CdPipelines{
		AppId:     appId,
		Pipelines: pipelines,
	}
	if len(pipelines) == 0 {
		err = &util.ApiError{Code: "404", HttpStatusCode: 200, UserMessage: "no cd pipeline found"}
	} else {
		err = nil
	}
	return cdPipelines, err
}

func (impl CiCdPipelineOrchestratorImpl) GetCdPipelinesForEnv(envId int, requestedAppIds []int) (cdPipelines *bean.CdPipelines, err error) {
	var dbPipelines []*pipelineConfig.Pipeline
	appIds := make([]int, 0, len(requestedAppIds)*envId)
	if len(requestedAppIds) > 0 {
		appIds, err = impl.pipelineRepository.FindActivePipelineAppIdsByInFilter(envId, requestedAppIds)
	} else {
		appIds, err = impl.pipelineRepository.FindActivePipelineAppIdsByEnvId(envId)
	}
	if err != nil && !util.IsErrNoRows(err) {
		impl.logger.Errorw("error in fetching pipeline's appIds", "envId", envId, "requestedAppIds", requestedAppIds, "err", err)
		return nil, err
	}

	if len(appIds) == 0 {
		err = &util.ApiError{Code: "404", HttpStatusCode: http.StatusNotFound, UserMessage: "no cd pipeline found"}
		return cdPipelines, err
	}

	// fetch other environments also which are linked with this app
	dbPipelines, err = impl.pipelineRepository.FindActiveByAppIds(appIds)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error fetching pipelines for env id", "err", err)
		return nil, err
	}
	pipelineIdAndPrePostStageMapping, err := impl.getPipelineIdAndPrePostStageMapping(dbPipelines)
	if err != nil {
		impl.logger.Errorw("error in fetching pipelineIdAndPrePostStageMapping", "err", err)
		return nil, err
	}
	appIdToGitOpsConfiguredMap, err := impl.chartReadService.IsGitOpsRepoConfiguredForDevtronApps(appIds)
	if err != nil {
		impl.logger.Errorw("error in fetching latest chart details for app by appId")
		return nil, err
	}
	pipelines := make([]*bean.CDPipelineConfigObject, 0, len(dbPipelines))
	cdPipelineMinObjs := sliceUtil.NewSliceFromFuncExec(dbPipelines, func(dbPipeline *pipelineConfig.Pipeline) *bean.CDPipelineMinConfig {
		return adapter2.NewCDPipelineMinConfigFromModel(dbPipeline)
	})
	pipelineIdDeploymentTypeMap, err := impl.deploymentConfigReadService.GetDeploymentAppTypeForCDInBulk(cdPipelineMinObjs, appIdToGitOpsConfiguredMap)
	if err != nil {
		impl.logger.Errorw("error, GetDeploymentAppTypeForCDInBulk", "pipelines", dbPipelines, "err", err)
		return nil, err
	}
	for _, dbPipeline := range dbPipelines {
		var deploymentAppType, releaseMode string
		var isGitOpsRepoNotConfigured bool
		if envDeploymentConfigMin, ok := pipelineIdDeploymentTypeMap[dbPipeline.Id]; ok {
			deploymentAppType = envDeploymentConfigMin.DeploymentAppType
			releaseMode = envDeploymentConfigMin.ReleaseMode
			isGitOpsRepoNotConfigured = !envDeploymentConfigMin.IsGitOpsRepoConfigured
		} else {
			// error handling if data is not found; as it is a required field
			impl.logger.Errorw("error in fetching deploymentAppType and release mode for pipeline", "pipelineId", dbPipeline.Id, "pipelineIdDeploymentTypeMap", pipelineIdDeploymentTypeMap)
			return nil, fmt.Errorf("error in fetching deploymentAppType and release mode for pipeline")
		}
		pipeline := &bean.CDPipelineConfigObject{
			Id:                        dbPipeline.Id,
			Name:                      dbPipeline.Name,
			EnvironmentId:             dbPipeline.EnvironmentId,
			EnvironmentName:           dbPipeline.Environment.Name,
			CiPipelineId:              dbPipeline.CiPipelineId,
			TriggerType:               dbPipeline.TriggerType,
			RunPreStageInEnv:          dbPipeline.RunPreStageInEnv,
			RunPostStageInEnv:         dbPipeline.RunPostStageInEnv,
			DeploymentAppType:         deploymentAppType,
			ReleaseMode:               releaseMode,
			AppName:                   dbPipeline.App.AppName,
			AppId:                     dbPipeline.AppId,
			TeamId:                    dbPipeline.App.TeamId,
			EnvironmentIdentifier:     dbPipeline.Environment.EnvironmentIdentifier,
			IsVirtualEnvironment:      dbPipeline.Environment.IsVirtualEnvironment,
			IsGitOpsRepoNotConfigured: isGitOpsRepoNotConfigured,
		}
		if len(dbPipeline.PreStageConfig) > 0 {
			preStage := bean.CdStage{}
			preStage.Name = "Pre-Deployment"
			preStage.Config = dbPipeline.PreStageConfig
			preStage.TriggerType = dbPipeline.PreTriggerType
			pipeline.PreStage = preStage
		}
		if len(dbPipeline.PostStageConfig) > 0 {
			postStage := bean.CdStage{}
			postStage.Name = "Post-Deployment"
			postStage.Config = dbPipeline.PostStageConfig
			postStage.TriggerType = dbPipeline.PostTriggerType
			pipeline.PostStage = postStage
		}
		if pipelineStages, ok := pipelineIdAndPrePostStageMapping[dbPipeline.Id]; ok {
			pipeline.PreDeployStage = pipelineStages[0]
			pipeline.PostDeployStage = pipelineStages[1]
		}

		if dbPipeline.PreStageConfigMapSecretNames != "" {
			preStageConfigmapSecrets := bean.PreStageConfigMapSecretNames{}
			err = json.Unmarshal([]byte(dbPipeline.PreStageConfigMapSecretNames), &preStageConfigmapSecrets)
			if err != nil {
				impl.logger.Errorw("unmarshal error", "err", err)
				return nil, err
			}
			pipeline.PreStageConfigMapSecretNames = preStageConfigmapSecrets
		}
		if dbPipeline.PostStageConfigMapSecretNames != "" {
			postStageConfigmapSecrets := bean.PostStageConfigMapSecretNames{}
			err = json.Unmarshal([]byte(dbPipeline.PostStageConfigMapSecretNames), &postStageConfigmapSecrets)
			if err != nil {
				impl.logger.Errorw("unmarshal error", "err", err)
				return nil, err
			}
			pipeline.PostStageConfigMapSecretNames = postStageConfigmapSecrets
		}

		pipelines = append(pipelines, pipeline)
	}
	cdPipelines = &bean.CdPipelines{
		Pipelines: pipelines,
	}
	if len(pipelines) == 0 {
		err = &util.ApiError{Code: "404", HttpStatusCode: 200, UserMessage: "no cd pipeline found"}
	} else {
		err = nil
	}
	return cdPipelines, err
}

func (impl CiCdPipelineOrchestratorImpl) GetCdPipelinesForAppAndEnv(appId int, envId int) (cdPipelines *bean.CdPipelines, err error) {
	dbPipelines, err := impl.pipelineRepository.FindActiveByAppIdAndEnvironmentId(appId, envId)
	if err != nil {
		impl.logger.Errorw("error in fetching cdPipeline", "appId", appId, "err", err)
	}
	pipelineIdAndPrePostStageMapping, err := impl.getPipelineIdAndPrePostStageMapping(dbPipelines)
	if err != nil {
		impl.logger.Errorw("error in fetching pipelineIdAndPrePostStageMapping", "err", err)
		return nil, err
	}
	var pipelines []*bean.CDPipelineConfigObject
	for _, dbPipeline := range dbPipelines {
		preStage := bean.CdStage{}
		if len(dbPipeline.PreStageConfig) > 0 {
			preStage.Name = "Pre-Deployment"
			preStage.Config = dbPipeline.PreStageConfig
			preStage.TriggerType = dbPipeline.PreTriggerType
		}
		postStage := bean.CdStage{}
		if len(dbPipeline.PostStageConfig) > 0 {
			postStage.Name = "Post-Deployment"
			postStage.Config = dbPipeline.PostStageConfig
			postStage.TriggerType = dbPipeline.PostTriggerType
		}

		preStageConfigmapSecrets := bean.PreStageConfigMapSecretNames{}
		postStageConfigmapSecrets := bean.PostStageConfigMapSecretNames{}

		if dbPipeline.PreStageConfigMapSecretNames != "" {
			err = json.Unmarshal([]byte(dbPipeline.PreStageConfigMapSecretNames), &preStageConfigmapSecrets)
			if err != nil {
				impl.logger.Error(err)
				return nil, err
			}
		}
		if dbPipeline.PostStageConfigMapSecretNames != "" {
			err = json.Unmarshal([]byte(dbPipeline.PostStageConfigMapSecretNames), &postStageConfigmapSecrets)
			if err != nil {
				impl.logger.Error(err)
				return nil, err
			}
		}
		env, err := impl.envRepository.FindById(envId)
		if err != nil {
			impl.logger.Error(err)
			return nil, err
		}
		isAppLevelGitOpsConfigured, err := impl.chartService.IsGitOpsRepoConfiguredForDevtronApp(appId)
		if err != nil {
			impl.logger.Errorw("error in fetching latest chart details for app by appId")
			return nil, err
		}
		// TODO Asutosh: why not getting deployment config ??
		pipeline := &bean.CDPipelineConfigObject{
			Id:                            dbPipeline.Id,
			Name:                          dbPipeline.Name,
			EnvironmentId:                 dbPipeline.EnvironmentId,
			CiPipelineId:                  dbPipeline.CiPipelineId,
			TriggerType:                   dbPipeline.TriggerType,
			PreStage:                      preStage,
			PostStage:                     postStage,
			PreStageConfigMapSecretNames:  preStageConfigmapSecrets,
			PostStageConfigMapSecretNames: postStageConfigmapSecrets,
			RunPreStageInEnv:              dbPipeline.RunPreStageInEnv,
			RunPostStageInEnv:             dbPipeline.RunPostStageInEnv,
			CdArgoSetup:                   env.Cluster.CdArgoSetup,
			IsGitOpsRepoNotConfigured:     !isAppLevelGitOpsConfigured,
		}
		if pipelineStages, ok := pipelineIdAndPrePostStageMapping[dbPipeline.Id]; ok {
			pipeline.PreDeployStage = pipelineStages[0]
			pipeline.PostDeployStage = pipelineStages[1]
		}
		pipelines = append(pipelines, pipeline)
	}
	cdPipelines = &bean.CdPipelines{
		AppId:     appId,
		Pipelines: pipelines,
	}
	return cdPipelines, nil
}

func (impl CiCdPipelineOrchestratorImpl) GetByEnvOverrideId(envOverrideId int) (*bean.CdPipelines, error) {
	dbPipelines, err := impl.pipelineRepository.GetByEnvOverrideId(envOverrideId)
	if err != nil {
		impl.logger.Errorw("error in fetching cdPipeline", "envOverrideId", envOverrideId, "err", err)
	}
	var pipelines []*bean.CDPipelineConfigObject
	for _, dbPipeline := range dbPipelines {
		pipeline := &bean.CDPipelineConfigObject{
			Id:            dbPipeline.Id,
			Name:          dbPipeline.Name,
			EnvironmentId: dbPipeline.EnvironmentId,
			CiPipelineId:  dbPipeline.CiPipelineId,
			TriggerType:   dbPipeline.TriggerType,
		}
		pipelines = append(pipelines, pipeline)
	}
	cdPipelines := &bean.CdPipelines{
		//AppId:     appId,
		Pipelines: pipelines,
	}
	return cdPipelines, nil
}

func (impl CiCdPipelineOrchestratorImpl) createDockerRepoIfNeeded(dockerRegistryId, dockerRepository string) error {
	dockerArtifactStore, err := impl.dockerArtifactStoreRepository.FindOne(dockerRegistryId)
	if err != nil {
		impl.logger.Errorw("error in fetching DockerRegistry  for update", "err", err, "registry", dockerRegistryId)
		return err
	}
	if dockerArtifactStore.RegistryType == dockerRegistryRepository.REGISTRYTYPE_ECR {
		err := impl.CreateEcrRepo(dockerRepository, dockerArtifactStore.AWSRegion, dockerArtifactStore.AWSAccessKeyId, dockerArtifactStore.AWSSecretAccessKey)
		if err != nil {
			impl.logger.Errorw("ecr repo creation failed while updating ci template", "err", err, "repo", dockerRepository)
			return err
		}
	}
	return nil
}
func (impl CiCdPipelineOrchestratorImpl) CreateEcrRepo(dockerRepository, AWSRegion, AWSAccessKeyId, AWSSecretAccessKey string) error {
	impl.logger.Debugw("attempting ecr repo creation ", "repo", dockerRepository)
	if impl.ciConfig.SkipCreatingEcrRepo {
		impl.logger.Warnw("not creating ecr repo, set SKIP_CREATING_ECR_REPO flag false to enable")
		return nil
	}
	err := util.CreateEcrRepo(dockerRepository, AWSRegion, AWSAccessKeyId, AWSSecretAccessKey)
	if err != nil {
		if errors1.IsAlreadyExists(err) {
			impl.logger.Warnw("this repo already exists!!, skipping repo creation", "repo", dockerRepository)
		} else {
			impl.logger.Errorw("ecr repo creation failed, it might be due to authorization or any other external "+
				"dependency. please create repo manually before triggering ci", "repo", dockerRepository, "err", err)
			return err
		}
	}
	return nil
}

func (impl CiCdPipelineOrchestratorImpl) AddPipelineToTemplate(createRequest *bean.CiConfigRequest, isSwitchCiPipelineRequest bool) (resp *bean.CiConfigRequest, err error) {
	for _, ciPipeline := range createRequest.CiPipelines {
		if !ciPipeline.PipelineType.IsValidPipelineType() {
			impl.logger.Debugw(" Invalid PipelineType", "ciPipeline.PipelineType", ciPipeline.PipelineType)
			errorMessage := fmt.Sprintf(bean2.PIPELINE_TYPE_IS_NOT_VALID, ciPipeline.PipelineType)
			return nil, util.DefaultApiError().WithHttpStatusCode(http.StatusBadRequest).WithInternalMessage(errorMessage).WithUserMessage(errorMessage)
		}
	}
	if createRequest.AppWorkflowId == 0 {
		// create workflow
		wf := &appWorkflow.AppWorkflow{
			Name:   beHelper.GetAppWorkflowName(createRequest.AppId),
			AppId:  createRequest.AppId,
			Active: true,
			AuditLog: sql.AuditLog{
				CreatedOn: time.Now(),
				UpdatedOn: time.Now(),
				CreatedBy: createRequest.UserId,
				UpdatedBy: createRequest.UserId,
			},
		}
		savedAppWf, err := impl.appWorkflowRepository.SaveAppWorkflow(wf)
		if err != nil {
			impl.logger.Errorw("err", err)
			return nil, err
		}
		// workflow creation ends
		createRequest.AppWorkflowId = savedAppWf.Id
	}
	//single ci in same wf validation
	workflowMapping, err := impl.appWorkflowRepository.FindWFCIMappingByWorkflowId(createRequest.AppWorkflowId)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching workflow mapping for ci validation", "err", err)
		return nil, err
	}

	if !isSwitchCiPipelineRequest && len(workflowMapping) > 0 {
		return nil, &util.ApiError{
			InternalMessage:   "pipeline already exists",
			UserDetailMessage: fmt.Sprintf("pipeline already exists in workflow"),
			UserMessage:       fmt.Sprintf("pipeline already exists in workflow")}
	}

	createRequest, err = impl.CreateCiConf(createRequest, createRequest.Id)
	if err != nil {
		return nil, err
	}
	return createRequest, err
}

func (impl CiCdPipelineOrchestratorImpl) GetSourceCiDownStreamFilters(ctx context.Context, sourceCiPipelineId int) (*bean2.SourceCiDownStreamEnv, error) {
	ctx, span := otel.Tracer("orchestrator").Start(ctx, "GetSourceCiDownStreamFilters")
	defer span.End()
	linkedCiPipelines, err := impl.ciPipelineRepository.GetLinkedCiPipelines(ctx, sourceCiPipelineId)
	if err != nil {
		impl.logger.Errorw("error in getting linked Ci pipelines for given source Ci pipeline Id ", "sourceCiPipelineId", sourceCiPipelineId, "err", err)
		return &bean2.SourceCiDownStreamEnv{
			EnvNames: []string{},
		}, err
	}
	envNames, err := impl.getAttachedEnvNamesByCiIds(ctx, linkedCiPipelines)
	if err != nil {
		impl.logger.Errorw("error in fetching environment names for linked Ci pipelines", "linkedCiPipelines", linkedCiPipelines, "err", err)
		return &bean2.SourceCiDownStreamEnv{
			EnvNames: []string{},
		}, err
	}
	res := &bean2.SourceCiDownStreamEnv{
		EnvNames: envNames,
	}
	return res, nil
}

func (impl CiCdPipelineOrchestratorImpl) getAttachedEnvNamesByCiIds(ctx context.Context, linkedCiPipelines []*pipelineConfig.CiPipeline) ([]string, error) {
	ctx, span := otel.Tracer("orchestrator").Start(ctx, "getAttachedEnvNamesByCiIds")
	defer span.End()
	var ciPipelineIds []int
	for _, ciPipeline := range linkedCiPipelines {
		ciPipelineIds = append(ciPipelineIds, ciPipeline.Id)
	}
	pipelines, err := impl.pipelineRepository.FindWithEnvironmentByCiIds(ctx, ciPipelineIds)
	if util.IsErrNoRows(err) {
		impl.logger.Info("no pipelines available for these ciPipelineIds", "ciPipelineIds", ciPipelineIds)
		return []string{}, nil
	} else if err != nil {
		impl.logger.Errorw("error in getting pipelines for these ciPipelineIds ", "ciPipelineIds", ciPipelineIds, "err", err)
		return nil, err
	}
	if pipelines == nil {
		impl.logger.Info("no pipelines available for these ciPipelineIds", "ciPipelineIds", ciPipelineIds)
		return []string{}, nil
	}
	var envNames []string
	for _, pipeline := range pipelines {
		if !slices.Contains(envNames, pipeline.Environment.Name) {
			envNames = append(envNames, pipeline.Environment.Name)
		}
	}
	return envNames, nil
}

func (impl CiCdPipelineOrchestratorImpl) GetSourceCiDownStreamInfo(ctx context.Context, sourceCIPipeline int, req *bean2.SourceCiDownStreamFilters) (pagination.PaginatedResponse[bean2.SourceCiDownStreamResponse], error) {
	ctx, span := otel.Tracer("orchestrator").Start(ctx, "GetSourceCiDownStreamInfo")
	defer span.End()
	response := pagination.NewPaginatedResponse[bean2.SourceCiDownStreamResponse]()
	queryReq := &pagination.RepositoryRequest{
		Order:  req.SortOrder,
		SortBy: req.SortBy,
		Limit:  req.Size,
		Offset: req.Offset,
	}
	linkedCIDetails, totalCount, err := impl.ciPipelineRepository.GetDownStreamInfo(ctx, sourceCIPipeline, req.SearchKey, req.EnvName, queryReq)
	if util.IsErrNoRows(err) {
		impl.logger.Info("no linked ci pipelines available", "SourceCIPipeline", sourceCIPipeline)
		return response, nil
	} else if err != nil {
		impl.logger.Errorw("error in getting linked ci pipelines", "SourceCIPipeline", sourceCIPipeline, "err", err)
		return response, err
	}
	response.UpdateTotalCount(totalCount)
	response.UpdateOffset(req.Offset)
	response.UpdateSize(req.Size)

	var pipelineIds []int
	for _, item := range linkedCIDetails {
		if item.PipelineId != 0 {
			pipelineIds = append(pipelineIds, item.PipelineId)
		}
	}

	latestWfrs, err := impl.cdWorkflowRepository.FindLatestRunnerByPipelineIdsAndRunnerType(ctx, pipelineIds, apiBean.CD_WORKFLOW_TYPE_DEPLOY)
	if util.IsErrNoRows(err) {
		impl.logger.Info("no deployments have been triggered yet", "pipelineIds", pipelineIds)
		// update the response with the pipelineConfig.LinkedCIDetails
		data := adapter.GetSourceCiDownStreamResponse(linkedCIDetails)
		response.PushData(data...)
		return response, nil
	} else if err != nil {
		impl.logger.Errorw("error in getting last deployment status", "pipelineIds", pipelineIds, "err", err)
		return response, err
	}
	data := adapter.GetSourceCiDownStreamResponse(linkedCIDetails, latestWfrs...)
	response.PushData(data...)
	return response, nil
}

func (impl *CiCdPipelineOrchestratorImpl) GetSourceCiPipelineForArtifact(ciPipeline pipelineConfig.CiPipeline) (*pipelineConfig.CiPipeline, error) {
	sourceCiPipeline := &ciPipeline
	if adapter.IsLinkedCD(ciPipeline) {
		sourceCdPipeline, err := impl.pipelineRepository.FindById(ciPipeline.ParentCiPipeline)
		if err != nil {
			impl.logger.Errorw("error in finding source cdPipeline for linked cd", "cdPipelineId", ciPipeline.ParentCiPipeline, "err", err)
			return nil, err
		}
		sourceCiPipeline, err = impl.ciPipelineRepository.FindOneWithAppData(sourceCdPipeline.CiPipelineId)
		if err != nil && !util.IsErrNoRows(err) {
			impl.logger.Errorw("error in finding ciPipeline for the cd pipeline", "CiPipelineId", sourceCdPipeline.Id, "CiPipelineId", sourceCdPipeline.CiPipelineId, "err", err)
			return nil, err
		}
	}
	return sourceCiPipeline, nil
}

func (impl *CiCdPipelineOrchestratorImpl) GetGitCommitEnvVarDataForCICDStage(gitTriggers map[int]pipelineConfig.GitCommit) (map[string]string, *gitSensor.WebhookAndCiData, error) {
	var webhookAndCiData *gitSensor.WebhookAndCiData
	var err error
	extraEnvVariables := make(map[string]string)
	if gitTriggers != nil {
		i := 1
		var gitCommitEnvVariables []types.GitMetadata

		for ciPipelineMaterialId, gitTrigger := range gitTriggers {
			extraEnvVariables[fmt.Sprintf("%s_%d", types.GIT_COMMIT_HASH_PREFIX, i)] = gitTrigger.Commit
			extraEnvVariables[fmt.Sprintf("%s_%d", types.GIT_SOURCE_TYPE_PREFIX, i)] = string(gitTrigger.CiConfigureSourceType)
			extraEnvVariables[fmt.Sprintf("%s_%d", types.GIT_SOURCE_VALUE_PREFIX, i)] = gitTrigger.CiConfigureSourceValue
			extraEnvVariables[fmt.Sprintf("%s_%d", types.GIT_REPO_URL_PREFIX, i)] = gitTrigger.GitRepoUrl

			gitCommitEnvVariables = append(gitCommitEnvVariables, types.GitMetadata{
				GitCommitHash:  gitTrigger.Commit,
				GitSourceType:  string(gitTrigger.CiConfigureSourceType),
				GitSourceValue: gitTrigger.CiConfigureSourceValue,
				GitRepoUrl:     gitTrigger.GitRepoUrl,
			})

			// CODE-BLOCK starts - store extra environment variables if webhook
			if gitTrigger.CiConfigureSourceType == constants2.SOURCE_TYPE_WEBHOOK {
				webhookDataId := gitTrigger.WebhookData.Id
				if webhookDataId > 0 {
					webhookDataRequest := &gitSensor.WebhookDataRequest{
						Id:                   webhookDataId,
						CiPipelineMaterialId: ciPipelineMaterialId,
					}
					webhookAndCiData, err = impl.GitSensorClient.GetWebhookData(context.Background(), webhookDataRequest)
					if err != nil {
						impl.logger.Errorw("err while getting webhook data from git-sensor", "err", err, "webhookDataRequest", webhookDataRequest)
						return nil, nil, err
					}
					if webhookAndCiData != nil {
						for extEnvVariableKey, extEnvVariableVal := range webhookAndCiData.ExtraEnvironmentVariables {
							extraEnvVariables[extEnvVariableKey] = extEnvVariableVal
						}
					}
				}
			}
			// CODE_BLOCK ends

			i++
		}
		gitMetadata, err := json.Marshal(&gitCommitEnvVariables)
		if err != nil {
			impl.logger.Errorw("err while marshaling git metdata", "err", err)
			return nil, nil, err
		}
		extraEnvVariables[plugin.GIT_METADATA] = string(gitMetadata)

		extraEnvVariables[types.GIT_SOURCE_COUNT] = strconv.Itoa(len(gitTriggers))
	}

	return extraEnvVariables, webhookAndCiData, nil
}

func (impl *CiCdPipelineOrchestratorImpl) GetWorkflowCacheConfig(appType helper.AppType, pipelineType string, pipelineWorkflowCacheConfig common2.WorkflowCacheConfigType) bean.WorkflowCacheConfig {
	if appType == helper.Job {
		return util4.GetWorkflowCacheConfig(pipelineWorkflowCacheConfig, impl.workflowCacheConfig.IgnoreJob)
	} else {
		if pipelineType == string(buildCommonBean.CI_JOB) {
			return util4.GetWorkflowCacheConfigWithBackwardCompatibility(pipelineWorkflowCacheConfig, impl.ciConfig.WorkflowCacheConfig, impl.workflowCacheConfig.IgnoreCIJob, impl.ciConfig.SkipCiJobBuildCachePushPull)
		} else {
			return util4.GetWorkflowCacheConfigWithBackwardCompatibility(pipelineWorkflowCacheConfig, impl.ciConfig.WorkflowCacheConfig, impl.workflowCacheConfig.IgnoreCI, impl.ciConfig.IgnoreDockerCacheForCI)
		}
	}
}
