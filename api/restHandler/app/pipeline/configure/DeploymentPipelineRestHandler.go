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

package configure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	models2 "github.com/devtron-labs/devtron/internal/sql/models"
	bean4 "github.com/devtron-labs/devtron/pkg/auth/user/bean"
	util3 "github.com/devtron-labs/devtron/pkg/auth/user/util"
	bean3 "github.com/devtron-labs/devtron/pkg/chart/bean"

	devtronAppGitOpConfigBean "github.com/devtron-labs/devtron/pkg/chart/gitOpsConfig/bean"
	"github.com/devtron-labs/devtron/pkg/policyGovernance/security/imageScanning/repository"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	bean2 "github.com/devtron-labs/devtron/api/bean"
	"github.com/devtron-labs/devtron/api/restHandler/common"
	"github.com/devtron-labs/devtron/internal/sql/repository/helper"
	"github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig"
	"github.com/devtron-labs/devtron/internal/util"
	"github.com/devtron-labs/devtron/pkg/auth/authorisation/casbin"
	"github.com/devtron-labs/devtron/pkg/bean"
	"github.com/devtron-labs/devtron/pkg/generateManifest"
	pipelineBean "github.com/devtron-labs/devtron/pkg/pipeline/bean"
	resourceGroup2 "github.com/devtron-labs/devtron/pkg/resourceGroup"
	"github.com/devtron-labs/devtron/pkg/resourceQualifiers"
	"github.com/devtron-labs/devtron/pkg/variables/models"
	util2 "github.com/devtron-labs/devtron/util"
	"github.com/go-pg/pg"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
)

type DeploymentHistoryResp struct {
	CdWorkflows                []pipelineBean.CdWorkflowWithArtifact `json:"cdWorkflows"`
	TagsEdiatable              bool                                  `json:"tagsEditable"`
	AppReleaseTagNames         []string                              `json:"appReleaseTagNames"` //unique list of tags exists in the app
	HideImageTaggingHardDelete bool                                  `json:"hideImageTaggingHardDelete"`
}

type DevtronAppDeploymentRestHandler interface {
	CreateCdPipeline(w http.ResponseWriter, r *http.Request)
	GetCdPipelineById(w http.ResponseWriter, r *http.Request)
	PatchCdPipeline(w http.ResponseWriter, r *http.Request)

	HandleChangeDeploymentRequest(w http.ResponseWriter, r *http.Request)
	HandleChangeDeploymentTypeRequest(w http.ResponseWriter, r *http.Request)
	HandleTriggerDeploymentAfterTypeChange(w http.ResponseWriter, r *http.Request)

	GetCdPipelines(w http.ResponseWriter, r *http.Request)
	GetCdPipelinesForAppAndEnv(w http.ResponseWriter, r *http.Request)

	GetArtifactsByCDPipeline(w http.ResponseWriter, r *http.Request)
	GetArtifactsForRollback(w http.ResponseWriter, r *http.Request)

	UpgradeForAllApps(w http.ResponseWriter, r *http.Request)

	IsReadyToTrigger(w http.ResponseWriter, r *http.Request)
	FetchCdWorkflowDetails(w http.ResponseWriter, r *http.Request)
	GetCdPipelinesByEnvironment(w http.ResponseWriter, r *http.Request)
	GetCdPipelinesByEnvironmentMin(w http.ResponseWriter, r *http.Request)

	ChangeChartRef(w http.ResponseWriter, r *http.Request)
	ValidateExternalAppLinkRequest(w http.ResponseWriter, r *http.Request)
}

type DevtronAppDeploymentConfigRestHandler interface {
	ConfigureDeploymentTemplateForApp(w http.ResponseWriter, r *http.Request)
	GetDeploymentTemplate(w http.ResponseWriter, r *http.Request)
	GetDefaultDeploymentTemplate(w http.ResponseWriter, r *http.Request)
	GetAppOverrideForDefaultTemplate(w http.ResponseWriter, r *http.Request)
	GetTemplateComparisonMetadata(w http.ResponseWriter, r *http.Request)
	GetDeploymentTemplateData(w http.ResponseWriter, r *http.Request)
	GetRestartWorkloadData(w http.ResponseWriter, r *http.Request)
	SaveGitOpsConfiguration(w http.ResponseWriter, r *http.Request)
	GetGitOpsConfiguration(w http.ResponseWriter, r *http.Request)

	EnvConfigOverrideCreate(w http.ResponseWriter, r *http.Request)
	EnvConfigOverrideUpdate(w http.ResponseWriter, r *http.Request)
	GetEnvConfigOverride(w http.ResponseWriter, r *http.Request)
	EnvConfigOverrideReset(w http.ResponseWriter, r *http.Request)

	UpdateAppOverride(w http.ResponseWriter, r *http.Request)
	GetConfigmapSecretsForDeploymentStages(w http.ResponseWriter, r *http.Request)
	GetDeploymentPipelineStrategy(w http.ResponseWriter, r *http.Request)
	GetDefaultDeploymentPipelineStrategy(w http.ResponseWriter, r *http.Request)

	EnvConfigOverrideCreateNamespace(w http.ResponseWriter, r *http.Request)

	DevtronAppDeploymentConfigRestHandlerEnt
}

type DevtronAppPrePostDeploymentRestHandler interface {
	GetStageStatus(w http.ResponseWriter, r *http.Request)
	GetPrePostDeploymentLogs(w http.ResponseWriter, r *http.Request)
	// CancelStage Cancel Pre/Post ArgoWorkflow execution
	CancelStage(w http.ResponseWriter, r *http.Request)
}

type DevtronAppDeploymentHistoryRestHandler interface {
	ListDeploymentHistory(w http.ResponseWriter, r *http.Request)
	DownloadArtifacts(w http.ResponseWriter, r *http.Request)
}

func (handler *PipelineConfigRestHandlerImpl) ConfigureDeploymentTemplateForApp(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var templateRequest bean3.TemplateRequest
	err = decoder.Decode(&templateRequest)
	templateRequest.UserId = userId
	if err != nil {
		handler.Logger.Errorw("request err, ConfigureDeploymentTemplateForApp", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartRefId := templateRequest.ChartRefId
	// VARIABLE_RESOLVE
	scope := resourceQualifiers.Scope{
		AppId: templateRequest.AppId,
	}
	validate, err2 := handler.deploymentTemplateValidationService.DeploymentTemplateValidate(r.Context(), templateRequest.ValuesOverride, chartRefId, scope)
	if !validate {
		common.WriteJsonResp(w, err2, nil, http.StatusBadRequest)
		return
	}

	handler.Logger.Infow("request payload, ConfigureDeploymentTemplateForApp", "payload", templateRequest)
	err = handler.validator.Struct(templateRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, ConfigureDeploymentTemplateForApp", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(templateRequest.AppId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := w.(http.CloseNotifier); ok {
		go func(done <-chan struct{}, closed <-chan bool) {
			select {
			case <-done:
			case <-closed:
				cancel()
			}
		}(ctx.Done(), cn.CloseNotify())
	}
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userMetadata := util3.GetUserMetadata(r.Context(), userId, isSuperAdmin)

	createResp, err := handler.draftAwareResourceService.Create(ctx, templateRequest, userMetadata)
	if err != nil {
		handler.Logger.Errorw("service err, ConfigureDeploymentTemplateForApp", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) CreateCdPipeline(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var cdPipeline bean.CdPipelines
	err = decoder.Decode(&cdPipeline)
	cdPipeline.UserId = userId
	if err != nil {
		handler.Logger.Errorw("request err, CreateCdPipeline", "err", err, "payload", cdPipeline)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, CreateCdPipeline", "payload", cdPipeline)
	userUploaded, err := handler.chartService.CheckIfChartRefUserUploadedByAppId(cdPipeline.AppId)
	if !userUploaded {
		err = handler.validator.Struct(cdPipeline)
		if err != nil {
			handler.Logger.Errorw("validation err, CreateCdPipeline", "err", err, "payload", cdPipeline)
			common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
	}

	handler.Logger.Debugw("pipeline create request ", "req", cdPipeline)
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(cdPipeline.AppId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	if app.AppType == helper.Job {
		common.WriteJsonResp(w, fmt.Errorf("cannot create cd-pipeline for job"), "cannot create cd-pipeline for job", http.StatusBadRequest)
		return
	}

	// RBAC
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	ok := true
	for _, deploymentPipeline := range cdPipeline.Pipelines {

		if deploymentPipeline.IsLinkedRelease() {
			//only super admin is allowed to link pipeline to external helm release/ acd Application
			if ok := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*"); !ok {
				common.WriteJsonResp(w, errors.New("unauthorized User"), nil, http.StatusForbidden)
				return
			}
		}

		//handling case of change of source from CI_PIPELINE to external-ci type (other change of type any -> any has been handled in ci-pipeline/patch api)
		if deploymentPipeline.IsSwitchCiPipelineRequest() {
			cdPipelines, err := handler.getCdPipelinesForCdPatchRbac(deploymentPipeline)
			if err != nil && !errors.Is(err, pg.ErrNoRows) {
				handler.Logger.Errorw("error in finding cdPipelines by deploymentPipeline", "deploymentPipeline", deploymentPipeline, "err", err)
				common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
				return
			}
			ok = handler.checkCiPatchAccess(token, resourceName, cdPipelines)

		} else if deploymentPipeline.EnvironmentId > 0 {
			object := handler.enforcerUtil.GetAppRBACByAppNameAndEnvId(app.AppName, deploymentPipeline.EnvironmentId)
			handler.Logger.Debugw("Triggered Request By:", "object", object)
			ok = handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionCreate, object)
		}
		if !ok {
			common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
			return
		}
	}
	// RBAC
	createResp, err := handler.pipelineBuilder.CreateCdPipelines(&cdPipeline, r.Context())

	if err != nil {
		handler.Logger.Errorw("service err, CreateCdPipeline", "err", err, "payload", cdPipeline)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) PatchCdPipeline(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var cdPipeline bean.CDPatchRequest
	err = decoder.Decode(&cdPipeline)
	cdPipeline.UserId = userId
	if err != nil {
		handler.Logger.Errorw("request err, PatchCdPipeline", "err", err, "payload", cdPipeline)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	v := r.URL.Query()
	forceDelete := false
	cascadeDelete := true
	force := v.Get("force")
	cascade := v.Get("cascade")
	if len(force) > 0 && len(cascade) > 0 {
		handler.Logger.Errorw("request err, PatchCdPipeline", "err", fmt.Errorf("cannot perform both cascade and force delete"), "payload", cdPipeline)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	if len(force) > 0 {
		forceDelete, err = strconv.ParseBool(force)
		if err != nil {
			handler.Logger.Errorw("request err, PatchCdPipeline", "err", err, "payload", cdPipeline)
			common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
	} else if len(cascade) > 0 {
		cascadeDelete, err = strconv.ParseBool(cascade)
		if err != nil {
			handler.Logger.Errorw("request err, PatchCdPipeline", "err", err, "payload", cdPipeline)
			common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
	}
	cdPipeline.ForceDelete = forceDelete
	cdPipeline.NonCascadeDelete = !cascadeDelete
	handler.Logger.Infow("request payload, PatchCdPipeline", "payload", cdPipeline)
	err = handler.validator.StructPartial(cdPipeline, "AppId", "Action")
	if err == nil {
		if cdPipeline.Action == bean.CD_CREATE {
			err = handler.validator.Struct(cdPipeline.Pipeline)
		} else if cdPipeline.Action == bean.CD_DELETE {
			err = handler.validator.Var(cdPipeline.Pipeline.Id, "gt=0")
		} else if cdPipeline.Action == bean.CD_DELETE_PARTIAL {
			err = handler.validator.Var(cdPipeline.Pipeline.Id, "gt=0")
		}
	}
	if err != nil {
		handler.Logger.Errorw("validation err, PatchCdPipeline", "err", err, "payload", cdPipeline)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(cdPipeline.AppId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionUpdate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	object := handler.enforcerUtil.GetAppRBACByAppIdAndPipelineId(cdPipeline.AppId, cdPipeline.Pipeline.Id)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionUpdate, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	createResp, err := handler.pipelineBuilder.PatchCdPipelines(&cdPipeline, r.Context())
	if err != nil {
		handler.Logger.Errorw("service err, PatchCdPipeline", "err", err, "payload", cdPipeline)

		if errors.As(err, &models.ValidationError{}) {
			common.WriteJsonResp(w, err, nil, http.StatusPreconditionFailed)
		} else {
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		}
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

// HandleChangeDeploymentRequest changes the deployment app type for all pipelines in all apps for a given environment.
func (handler *PipelineConfigRestHandlerImpl) HandleChangeDeploymentRequest(w http.ResponseWriter, r *http.Request) {

	// Auth check
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	// Retrieving and parsing request body
	decoder := json.NewDecoder(r.Body)
	var deploymentAppTypeChangeRequest *bean.DeploymentAppTypeChangeRequest
	err = decoder.Decode(&deploymentAppTypeChangeRequest)
	if err != nil {
		handler.Logger.Errorw("request err, HandleChangeDeploymentRequest", "err", err, "payload",
			deploymentAppTypeChangeRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	deploymentAppTypeChangeRequest.UserId = userId

	// Validate incoming request
	err = handler.validator.Struct(deploymentAppTypeChangeRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, HandleChangeDeploymentRequest", "err", err, "payload",
			deploymentAppTypeChangeRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// Only super-admin access
	token := r.Header.Get("token")
	if ok := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionDelete, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}

	// Retrieve argocd token

	ctx := r.Context()
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userEmail := util2.GetEmailFromContext(ctx)
	userMetadata := &bean4.UserMetadata{
		UserEmailId:      userEmail,
		IsUserSuperAdmin: isSuperAdmin,
		UserId:           userId,
	}
	resp, err := handler.pipelineBuilder.ChangeDeploymentType(ctx, deploymentAppTypeChangeRequest, userMetadata)

	if err != nil {
		nErr := errors.New("failed to change deployment type with error msg: " + err.Error())
		handler.Logger.Errorw(err.Error(),
			"payload", deploymentAppTypeChangeRequest,
			"err", err)

		common.WriteJsonResp(w, nErr, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
	return
}

func (handler *PipelineConfigRestHandlerImpl) HandleChangeDeploymentTypeRequest(w http.ResponseWriter, r *http.Request) {

	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var deploymentTypeChangeRequest *bean.DeploymentAppTypeChangeRequest
	err = decoder.Decode(&deploymentTypeChangeRequest)
	if err != nil {
		handler.Logger.Errorw("request err, HandleChangeDeploymentTypeRequest", "err", err, "payload",
			deploymentTypeChangeRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	deploymentTypeChangeRequest.UserId = userId

	err = handler.validator.Struct(deploymentTypeChangeRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, HandleChangeDeploymentTypeRequest", "err", err, "payload",
			deploymentTypeChangeRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	token := r.Header.Get("token")
	if ok := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionDelete, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}

	ctx := r.Context()
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userEmail := util2.GetEmailFromContext(ctx)
	userMetadata := &bean4.UserMetadata{
		UserEmailId:      userEmail,
		IsUserSuperAdmin: isSuperAdmin,
		UserId:           userId,
	}
	resp, err := handler.pipelineBuilder.ChangePipelineDeploymentType(ctx, deploymentTypeChangeRequest, userMetadata)

	if err != nil {
		handler.Logger.Errorw(err.Error(), "payload", deploymentTypeChangeRequest, "err", err)

		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
	return
}

func (handler *PipelineConfigRestHandlerImpl) HandleTriggerDeploymentAfterTypeChange(w http.ResponseWriter, r *http.Request) {

	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var deploymentAppTriggerRequest *bean.DeploymentAppTypeChangeRequest
	err = decoder.Decode(&deploymentAppTriggerRequest)
	if err != nil {
		handler.Logger.Errorw("request err, HandleChangeDeploymentTypeRequest", "err", err, "payload",
			deploymentAppTriggerRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	deploymentAppTriggerRequest.UserId = userId

	err = handler.validator.Struct(deploymentAppTriggerRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, HandleChangeDeploymentTypeRequest", "err", err, "payload",
			deploymentAppTriggerRequest)

		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	token := r.Header.Get("token")

	if ok := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionDelete, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}

	ctx := r.Context()
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userEmail := util2.GetEmailFromContext(ctx)
	userMetadata := &bean4.UserMetadata{
		UserEmailId:      userEmail,
		IsUserSuperAdmin: isSuperAdmin,
		UserId:           userId,
	}
	resp, err := handler.pipelineBuilder.TriggerDeploymentAfterTypeChange(ctx, deploymentAppTriggerRequest, userMetadata)

	if err != nil {
		handler.Logger.Errorw(err.Error(),
			"payload", deploymentAppTriggerRequest,
			"err", err)

		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
	return
}

func (handler *PipelineConfigRestHandlerImpl) ChangeChartRef(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var request bean3.ChartRefChangeRequest
	err = decoder.Decode(&request)
	if err != nil || request.EnvId == 0 || request.TargetChartRefId == 0 || request.AppId == 0 {
		handler.Logger.Errorw("request err, ChangeChartRef", "err", err, "payload", request)
		common.WriteJsonResp(w, err, request, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, EnvConfigOverrideCreate", "payload", request)
	envConfigProperties, err := handler.propertiesConfigService.GetLatestEnvironmentProperties(request.AppId, request.EnvId)
	if err != nil || envConfigProperties == nil {
		handler.Logger.Errorw("env properties not found, ChangeChartRef", "err", err, "payload", request)
		common.WriteJsonResp(w, err, "env properties not found", http.StatusNotFound)
		return
	}
	if !envConfigProperties.IsOverride {
		handler.Logger.Errorw("isOverride is not true, ChangeChartRef", "err", err, "payload", request)
		common.WriteJsonResp(w, err, "specific environment is not overridden", http.StatusUnprocessableEntity)
		return
	}
	token := r.Header.Get("token")
	ctx := util2.SetTokenInContext(r.Context(), token)
	var envMetrics bool
	envConfigProperties, envMetrics, err = handler.deploymentTemplateValidationService.ValidateChangeChartRefRequest(ctx, envConfigProperties, &request)
	if err != nil {
		handler.Logger.Errorw("validation err, ChangeChartRef", "err", err, "payload", request)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	envConfigProperties.UserId = userId
	request.EnvConfigProperties = envConfigProperties
	request.EnvMetrics = envMetrics
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(request.AppId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetEnvRBACNameByAppId(request.AppId, request.EnvId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionUpdate, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if cn, ok := w.(http.CloseNotifier); ok {
		go func(done <-chan struct{}, closed <-chan bool) {
			select {
			case <-done:
			case <-closed:
				cancel()
			}
		}(newCtx.Done(), cn.CloseNotify())
	}
	envConfigProperties.MergeStrategy = models2.MERGE_STRATEGY_REPLACE // always replace
	createResp, err := handler.propertiesConfigService.ChangeChartRefForEnvConfigOverride(newCtx, &request, userId)
	if err != nil {
		handler.Logger.Errorw("service err, ChangeChartRef", "err", err, "payload", request)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
	return
}

func (handler *PipelineConfigRestHandlerImpl) EnvConfigOverrideCreate(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var envConfigProperties pipelineBean.EnvironmentProperties
	err = decoder.Decode(&envConfigProperties)
	if err != nil {
		handler.Logger.Errorw("request err, EnvConfigOverrideCreate", "err", err, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	envConfigProperties.UserId = userId
	envConfigProperties.EnvironmentId = environmentId
	envConfigProperties.AppId = appId
	handler.Logger.Infow("request payload, EnvConfigOverrideCreate", "payload", envConfigProperties)

	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetEnvRBACNameByAppId(appId, environmentId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionUpdate, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	chartRefId := envConfigProperties.ChartRefId
	// VARIABLE_RESOLVE
	scope := resourceQualifiers.Scope{
		AppId:     appId,
		EnvId:     environmentId,
		ClusterId: envConfigProperties.ClusterId,
	}
	validate, err2 := handler.deploymentTemplateValidationService.DeploymentTemplateValidate(r.Context(), envConfigProperties.EnvOverrideValues, chartRefId, scope)
	if !validate {
		handler.Logger.Errorw("validation err, UpdateAppOverride", "err", err2, "payload", envConfigProperties)
		common.WriteJsonResp(w, err2, nil, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := w.(http.CloseNotifier); ok {
		go func(done <-chan struct{}, closed <-chan bool) {
			select {
			case <-done:
			case <-closed:
				cancel()
			}
		}(ctx.Done(), cn.CloseNotify())
	}
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userMetadata := util3.GetUserMetadata(r.Context(), userId, isSuperAdmin)
	createResp, err := handler.draftAwareResourceService.CreateEnvironmentPropertiesAndBaseIfNeeded(ctx, &envConfigProperties, userMetadata)
	if err != nil {
		handler.Logger.Errorw("service err, CreateEnvironmentPropertiesAndBaseIfNeeded", "payload", envConfigProperties, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) EnvConfigOverrideUpdate(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	// userId := getLoggedInUser(r)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var envConfigProperties pipelineBean.EnvironmentProperties
	err = decoder.Decode(&envConfigProperties)
	envConfigProperties.UserId = userId
	if err != nil {
		handler.Logger.Errorw("request err, EnvConfigOverrideUpdate", "err", err, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, EnvConfigOverrideUpdate", "payload", envConfigProperties)
	err = handler.validator.Struct(envConfigProperties)
	if err != nil {
		handler.Logger.Errorw("validation err, EnvConfigOverrideUpdate", "err", err, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	envConfigOverride, err := handler.propertiesConfigService.GetAppIdByChartEnvId(envConfigProperties.Id)
	if err != nil {
		handler.Logger.Errorw("service err, EnvConfigOverrideUpdate", "err", err, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	envConfigProperties.AppId = envConfigOverride.Chart.AppId
	appId := envConfigOverride.Chart.AppId
	envId := envConfigOverride.TargetEnvironment
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionUpdate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetEnvRBACNameByAppId(appId, envId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionUpdate, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	chartRefId := envConfigProperties.ChartRefId
	// VARIABLE_RESOLVE
	scope := resourceQualifiers.Scope{
		AppId:     appId,
		EnvId:     envId,
		ClusterId: envConfigProperties.ClusterId,
	}
	validate, err2 := handler.deploymentTemplateValidationService.DeploymentTemplateValidate(r.Context(), envConfigProperties.EnvOverrideValues, chartRefId, scope)
	if !validate {
		handler.Logger.Errorw("validation err, UpdateAppOverride", "err", err2, "payload", envConfigProperties)
		common.WriteJsonResp(w, err2, nil, http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userMetadata := util3.GetUserMetadata(r.Context(), userId, isSuperAdmin)
	createResp, err := handler.draftAwareResourceService.UpdateEnvironmentProperties(ctx, &envConfigProperties, token, userMetadata)
	if err != nil {
		handler.Logger.Errorw("service err, EnvConfigOverrideUpdate", "err", err, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetEnvConfigOverride(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartRefId, err := strconv.Atoi(vars["chartRefId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetEnvConfigOverride", "err", err, "payload", appId, environmentId, chartRefId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetEnvConfigOverride", "payload", appId, environmentId, chartRefId)
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	env, err := handler.propertiesConfigService.GetEnvironmentProperties(appId, environmentId, chartRefId)
	if err != nil {
		handler.Logger.Errorw("service err, GetEnvConfigOverride", "err", err, "payload", appId, environmentId, chartRefId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	schema, readme, err := handler.chartRefService.GetSchemaAndReadmeForTemplateByChartRefId(chartRefId)
	if err != nil {
		handler.Logger.Errorw("err in getting schema and readme, GetEnvConfigOverride", "err", err, "appId", appId, "chartRefId", chartRefId)
	}
	env.Schema = schema
	env.Readme = string(readme)
	common.WriteJsonResp(w, err, env, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetTemplateComparisonMetadata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC enforcer applying
	object := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "unauthorized user", http.StatusForbidden)
		return
	}
	// RBAC enforcer Ends

	resp, err := handler.deploymentTemplateService.FetchDeploymentsWithChartRefs(appId, envId)
	if err != nil {
		handler.Logger.Errorw("service err, FetchDeploymentsWithChartRefs", "err", err, "appId", appId, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetDeploymentTemplateData(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	var request generateManifest.DeploymentTemplateRequest
	err := decoder.Decode(&request)
	if err != nil {
		handler.Logger.Errorw("request err, GetDeploymentTemplate by API", "err", err, "GetYaluesAndManifest", request)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	token := r.Header.Get("token")
	// RBAC enforcer applying
	object := handler.enforcerUtil.GetAppRBACNameByAppId(request.AppId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "unauthorized user", http.StatusForbidden)
		return
	}

	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		handler.Logger.Errorw("request err, userId", "err", err, "payload", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionGet, "*")
	// RBAC enforcer Ends

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	ctx = util2.SetSuperAdminInContext(ctx, isSuperAdmin)
	defer cancel()
	// TODO fix
	resp, err := handler.deploymentTemplateService.GetDeploymentTemplate(ctx, request)
	if err != nil {
		handler.Logger.Errorw("service err, GetEnvConfigOverride", "err", err, "payload", request)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetRestartWorkloadData(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	envId, err := common.ExtractIntQueryParam(w, r, "envId", 0)
	if err != nil {
		return
	}
	appIds, err := common.ExtractIntArrayQueryParam(w, r, "appIds")
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	// RBAC enforcer applying
	token := r.Header.Get(common.TokenHeaderKey)
	request := handler.filterAuthorizedResourcesForGroup(appIds, envId, token)
	if len(request) == 0 {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	resp, err := handler.deploymentTemplateService.GetRestartWorkloadData(ctx, request, envId)
	if err != nil {
		handler.Logger.Errorw("service err, GetRestartWorkloadData", "resp", resp, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) filterAuthorizedResourcesForGroup(appIds []int, envId int, token string) []int {

	appToEnv := make(map[int][]int)
	for _, appId := range appIds {
		appToEnv[appId] = []int{envId}
	}
	rbacObjectToApp := make(map[string]int)
	rbacObjects := make([]string, 0)

	objectMap := handler.enforcerUtil.GetRbacObjectsByEnvIdsAndAppIdBatch(appToEnv)

	for _, appId := range appIds {

		object := objectMap[appId][envId]
		rbacObjectToApp[object] = appId
		rbacObjects = append(rbacObjects, object)

	}

	authorizedApps := make([]int, 0)
	results := handler.enforcer.EnforceInBatch(token, casbin.ResourceEnvironment, casbin.ActionGet, rbacObjects)
	for object, isAllowed := range results {
		if isAllowed {
			authorizedApps = append(authorizedApps, rbacObjectToApp[object])
		}
	}

	return authorizedApps
}

func (handler *PipelineConfigRestHandlerImpl) GetDeploymentTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		handler.Logger.Error(err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartRefId, err := strconv.Atoi(vars["chartRefId"])
	if err != nil {
		handler.Logger.Error(err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetDeploymentTemplate", "appId", appId, "chartRefId", chartRefId)
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	appConfigResponse, err := handler.chartService.GetDeploymentTemplateDataByAppIdAndCharRefId(appId, chartRefId)
	if err != nil {
		handler.Logger.Errorw("refChartDir Not Found err, JsonSchemaExtractFromFile", err)
		common.WriteJsonResp(w, err, nil, http.StatusForbidden)
		return
	}
	common.WriteJsonResp(w, nil, appConfigResponse, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetDefaultDeploymentTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		handler.Logger.Error("error in getting appId path param, GetDefaultDeploymentTemplate", "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartRefId, err := strconv.Atoi(vars["chartRefId"])
	if err != nil {
		handler.Logger.Error("error in getting chartRefId path param, GetDefaultDeploymentTemplate", "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	obj := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, obj); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "unauthorized user", http.StatusForbidden)
		return
	}
	defaultTemplate, _, err := handler.chartRefService.GetAppOverrideForDefaultTemplate(chartRefId)
	if err != nil {
		handler.Logger.Errorw("error in getting default deployment template, GetDefaultDeploymentTemplate", "err", err, "appId", appId, "chartRefId", chartRefId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, defaultTemplate, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetCdPipelines(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetCdPipelines", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetCdPipelines", "appId", appId)
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelines", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	ciConf, err := handler.pipelineBuilder.GetCdPipelinesForApp(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelines", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	common.WriteJsonResp(w, err, ciConf, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetCdPipelinesForAppAndEnv(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetCdPipelinesForAppAndEnv", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetCdPipelinesForAppAndEnv", "err", err, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetCdPipelinesForAppAndEnv", "appId", appId, "envId", envId)
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelinesForAppAndEnv", "err", err, "appId", appId, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	// rbac
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetEnvRBACNameByAppId(appId, envId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// rbac

	cdPipelines, err := handler.pipelineBuilder.GetCdPipelinesForAppAndEnv(appId, envId)
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelinesForAppAndEnv", "err", err, "appId", appId, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, cdPipelines, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetArtifactsByCDPipeline(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	cdPipelineId, err := strconv.Atoi(vars["cd_pipeline_id"])
	if err != nil {
		handler.Logger.Errorw("request err, GetArtifactsByCDPipeline", "cdPipelineId", cdPipelineId, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	stage := r.URL.Query().Get("stage")
	if len(stage) == 0 {
		stage = pipelineBean.WorkflowTypePre
	}
	searchString := ""
	search := r.URL.Query().Get("search")
	if len(search) != 0 {
		searchString = search
	}

	offset := 0
	limit := 10
	offsetQueryParam := r.URL.Query().Get("offset")
	if offsetQueryParam != "" {
		offset, err = strconv.Atoi(offsetQueryParam)
		if err != nil || offset < 0 {
			handler.Logger.Errorw("request err, GetArtifactsForRollback", "offsetQueryParam", offsetQueryParam, "err", err)
			common.WriteJsonResp(w, err, "invalid offset", http.StatusBadRequest)
			return
		}
	}

	sizeQueryParam := r.URL.Query().Get("size")
	if sizeQueryParam != "" {
		limit, err = strconv.Atoi(sizeQueryParam)
		if err != nil {
			handler.Logger.Errorw("request err, GetArtifactsForRollback", "sizeQueryParam", sizeQueryParam, "err", err)
			common.WriteJsonResp(w, err, "invalid size", http.StatusBadRequest)
			return
		}
	}
	handler.Logger.Infow("request payload, GetArtifactsByCDPipeline", "cdPipelineId", cdPipelineId, "stage", stage)

	pipeline, err := handler.pipelineBuilder.FindPipelineById(cdPipelineId)
	if err != nil {
		handler.Logger.Errorw("service err, FindPipelineById", "stage", stage, "cdPipelineId", cdPipelineId, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// rbac block starts from here
	object := handler.enforcerUtil.GetAppRBACName(pipeline.App.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// rbac for edit tags access
	triggerAccess := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionTrigger, object)
	// rbac
	object = handler.enforcerUtil.GetAppRBACByAppNameAndEnvId(pipeline.App.AppName, pipeline.EnvironmentId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// rbac block ends here
	artifactsListFilterOptions := &bean2.ArtifactsListFilterOptions{
		Limit:        limit,
		Offset:       offset,
		SearchString: searchString,
	}

	// RetrieveArtifactsByCDPipeline is deprecated and method is removed from code
	// ciArtifactResponse, err = handler.pipelineBuilder.RetrieveArtifactsByCDPipeline(pipeline, bean2.WorkflowType(stage))

	ciArtifactResponse, err := handler.pipelineBuilder.RetrieveArtifactsByCDPipelineV2(pipeline, bean2.WorkflowType(stage), artifactsListFilterOptions)
	if err != nil {
		handler.Logger.Errorw("service err, GetArtifactsByCDPipeline", "cdPipelineId", cdPipelineId, "stage", stage, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	appTags, err := handler.imageTaggingReadService.GetUniqueTagsByAppId(pipeline.AppId)
	if err != nil {
		handler.Logger.Errorw("service err, GetTagsByAppId", "appId", pipeline.AppId, "err", err)
		common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusInternalServerError)
		return
	}

	ciArtifactResponse.AppReleaseTagNames = appTags

	prodEnvExists, err := handler.imageTaggingService.GetProdEnvByCdPipelineId(pipeline.Id)
	ciArtifactResponse.TagsEditable = prodEnvExists && triggerAccess
	ciArtifactResponse.HideImageTaggingHardDelete = handler.imageTaggingService.IsHardDeleteHidden()
	if err != nil {
		handler.Logger.Errorw("service err, GetProdEnvByCdPipelineId", "cdPipelineId", pipeline.Id, "err", err)
		common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusInternalServerError)
		return
	}

	var digests []string
	for _, item := range ciArtifactResponse.CiArtifacts {
		if len(item.ImageDigest) > 0 {
			digests = append(digests, item.ImageDigest)
		}
	}

	if len(digests) > 0 {
		// vulnerableMap := make(map[string]bool)
		cvePolicy, severityPolicy, err := handler.policyService.GetApplicablePolicy(pipeline.Environment.ClusterId,
			pipeline.EnvironmentId,
			pipeline.AppId,
			pipeline.App.AppType == helper.ChartStoreApp)

		if err != nil {
			handler.Logger.Errorw("service err, GetArtifactsByCDPipeline", "err", err, "cdPipelineId", cdPipelineId, "stage", stage)
		}

		// get image scan results from DB for given digests
		imageScanResults, err := handler.imageScanResultReadService.FindByImageDigests(digests)
		// ignore error
		if err != nil && err != pg.ErrNoRows {
			handler.Logger.Errorw("service err, FindByImageDigests", "err", err, "cdPipelineId", cdPipelineId, "stage", stage, "digests", digests)
		}

		// build digest vs cve-stores
		digestVsCveStores := make(map[string][]*repository.CveStore)
		for _, result := range imageScanResults {
			imageHash := result.ImageScanExecutionHistory.ImageHash

			// For an imageHash, append all cveStores
			if val, ok := digestVsCveStores[imageHash]; !ok {

				// configuring size as len of ImageScanExecutionResult assuming all the
				// scan results could belong to a single hash
				cveStores := make([]*repository.CveStore, 0, len(imageScanResults))
				cveStores = append(cveStores, &result.CveStore)
				digestVsCveStores[imageHash] = cveStores

			} else {
				// append to existing one
				digestVsCveStores[imageHash] = append(val, &result.CveStore)
			}
		}

		var ciArtifactsFinal []bean.CiArtifactBean
		for _, item := range ciArtifactResponse.CiArtifacts {

			// ignore cve check if scan is not enabled
			if !item.ScanEnabled {
				ciArtifactsFinal = append(ciArtifactsFinal, item)
				continue
			}

			cveStores, _ := digestVsCveStores[item.ImageDigest]
			item.IsVulnerable = handler.policyService.HasBlockedCVE(cveStores, cvePolicy, severityPolicy)
			ciArtifactsFinal = append(ciArtifactsFinal, item)
		}
		ciArtifactResponse.CiArtifacts = ciArtifactsFinal
	}

	common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetAppOverrideForDefaultTemplate(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetAppOverrideForDefaultTemplate", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartRefId, err := strconv.Atoi(vars["chartRefId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetAppOverrideForDefaultTemplate", "err", err, "chartRefId", chartRefId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC
	object := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC

	appOverride, _, err := handler.chartRefService.GetAppOverrideForDefaultTemplate(chartRefId)
	if err != nil {
		handler.Logger.Errorw("service err, UpdateCiTemplate", "err", err, "appId", appId, "chartRefId", chartRefId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, appOverride, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) UpdateAppOverride(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	var templateRequest bean3.TemplateRequest
	err = decoder.Decode(&templateRequest)
	templateRequest.UserId = userId
	if err != nil {
		handler.Logger.Errorw("request err, UpdateAppOverride", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	err = handler.validator.Struct(templateRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, UpdateAppOverride", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, UpdateAppOverride", "payload", templateRequest)

	token := r.Header.Get("token")
	ctx := r.Context()
	_, span := otel.Tracer("orchestrator").Start(ctx, "pipelineBuilder.GetApp")
	app, err := handler.pipelineBuilder.GetApp(templateRequest.AppId)
	span.End()
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	chartRefId := templateRequest.ChartRefId
	// VARIABLE_RESOLVE
	scope := resourceQualifiers.Scope{
		AppId: templateRequest.AppId,
	}
	_, span = otel.Tracer("orchestrator").Start(ctx, "chartService.DeploymentTemplateValidate")
	validate, err2 := handler.deploymentTemplateValidationService.DeploymentTemplateValidate(ctx, templateRequest.ValuesOverride, chartRefId, scope)
	span.End()
	if !validate {
		handler.Logger.Errorw("validation err, UpdateAppOverride", "err", err2, "payload", templateRequest)
		common.WriteJsonResp(w, err2, nil, http.StatusBadRequest)
		return
	}
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userMetadata := util3.GetUserMetadata(r.Context(), userId, isSuperAdmin)

	_, span = otel.Tracer("orchestrator").Start(ctx, "chartService.UpdateAppOverride")
	createResp, err := handler.draftAwareResourceService.UpdateAppOverride(ctx, &templateRequest, token, userMetadata)
	span.End()
	if err != nil {
		handler.Logger.Errorw("service err, UpdateAppOverride", "err", err, "payload", templateRequest)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)

}
func (handler *PipelineConfigRestHandlerImpl) GetArtifactsForRollback(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	cdPipelineId, err := strconv.Atoi(vars["cd_pipeline_id"])
	if err != nil {
		handler.Logger.Errorw("request err, GetArtifactsForRollback", "err", err, "cdPipelineId", cdPipelineId)
		common.WriteJsonResp(w, err, "invalid request", http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetArtifactsForRollback", "cdPipelineId", cdPipelineId)
	token := r.Header.Get("token")
	deploymentPipeline, err := handler.pipelineBuilder.FindPipelineById(cdPipelineId)
	if err != nil {
		handler.Logger.Errorw("service err, GetArtifactsForRollback", "err", err, "cdPipelineId", cdPipelineId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	app, err := handler.pipelineBuilder.GetApp(deploymentPipeline.AppId)
	if err != nil {
		handler.Logger.Errorw("service err, GetArtifactsForRollback", "err", err, "cdPipelineId", cdPipelineId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	offsetQueryParam := r.URL.Query().Get("offset")
	offset, err := strconv.Atoi(offsetQueryParam)
	if offsetQueryParam == "" || err != nil {
		handler.Logger.Errorw("request err, GetArtifactsForRollback", "err", err, "offsetQueryParam", offsetQueryParam)
		common.WriteJsonResp(w, err, "invalid offset", http.StatusBadRequest)
		return
	}
	sizeQueryParam := r.URL.Query().Get("size")
	limit, err := strconv.Atoi(sizeQueryParam)
	if sizeQueryParam == "" || err != nil {
		handler.Logger.Errorw("request err, GetArtifactsForRollback", "err", err, "sizeQueryParam", sizeQueryParam)
		common.WriteJsonResp(w, err, "invalid size", http.StatusBadRequest)
		return
	}
	searchString := r.URL.Query().Get("search")

	// rbac block starts from here
	object := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object = handler.enforcerUtil.GetAppRBACByAppNameAndEnvId(app.AppName, deploymentPipeline.EnvironmentId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// rbac block ends here
	// rbac for edit tags access
	var ciArtifactResponse bean.CiArtifactResponse
	triggerAccess := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionTrigger, object)

	ciArtifactResponse, err = handler.pipelineBuilder.FetchArtifactForRollbackV2(cdPipelineId, app.Id, offset, limit, searchString, app, deploymentPipeline)

	if err != nil {
		handler.Logger.Errorw("service err, GetArtifactsForRollback", "err", err, "cdPipelineId", cdPipelineId)
		common.WriteJsonResp(w, err, "unable to fetch artifacts", http.StatusInternalServerError)
		return
	}
	appTags, err := handler.imageTaggingReadService.GetUniqueTagsByAppId(app.Id)
	if err != nil {
		handler.Logger.Errorw("service err, GetTagsByAppId", "err", err, "appId", app.Id)
		common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusInternalServerError)
		return
	}

	ciArtifactResponse.AppReleaseTagNames = appTags

	prodEnvExists, err := handler.imageTaggingService.GetProdEnvByCdPipelineId(cdPipelineId)
	ciArtifactResponse.TagsEditable = prodEnvExists && triggerAccess
	ciArtifactResponse.HideImageTaggingHardDelete = handler.imageTaggingService.IsHardDeleteHidden()
	if err != nil {
		handler.Logger.Errorw("service err, GetProdEnvByCdPipelineId", "err", err, "cdPipelineId", app.Id)
		common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, ciArtifactResponse, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) EnvConfigOverrideReset(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, EnvConfigOverrideReset", "appId", appId, "environmentId", environmentId)
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		handler.Logger.Errorw("service err, EnvConfigOverrideReset", "err", err, "appId", appId, "environmentId", environmentId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionDelete, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetAppRBACByAppNameAndEnvId(app.AppName, environmentId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionDelete, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	isSuperAdmin := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*")
	userMetadata := util3.GetUserMetadata(r.Context(), userId, isSuperAdmin)
	envProperties := &pipelineBean.EnvironmentProperties{
		Id:            id,
		EnvironmentId: environmentId,
		UserId:        userId,
		AppId:         appId,
	}
	isSuccess, err := handler.draftAwareResourceService.ResetEnvironmentProperties(ctx, envProperties, userMetadata)
	if err != nil {
		handler.Logger.Errorw("service err, EnvConfigOverrideReset", "err", err, "appId", appId, "environmentId", environmentId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, isSuccess, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) ListDeploymentHistory(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	offsetQueryParam := r.URL.Query().Get("offset")
	offset, err := strconv.Atoi(offsetQueryParam)
	if offsetQueryParam == "" || err != nil {
		handler.Logger.Errorw("request err, ListDeploymentHistory", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "offset", offset)
		common.WriteJsonResp(w, err, "invalid offset", http.StatusBadRequest)
		return
	}
	sizeQueryParam := r.URL.Query().Get("size")
	limit, err := strconv.Atoi(sizeQueryParam)
	if sizeQueryParam == "" || err != nil {
		handler.Logger.Errorw("request err, ListDeploymentHistory", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "sizeQueryParam", sizeQueryParam)
		common.WriteJsonResp(w, err, "invalid size", http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, ListDeploymentHistory", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "offset", offset)
	// RBAC CHECK
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC CHECK
	resp := DeploymentHistoryResp{}
	wfs, err := handler.cdHandler.GetCdBuildHistory(appId, environmentId, pipelineId, offset, limit)
	resp.CdWorkflows = wfs
	if err != nil {
		handler.Logger.Errorw("service err, List", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "offset", offset)
		common.WriteJsonResp(w, err, resp, http.StatusInternalServerError)
		return
	}

	appTags, err := handler.imageTaggingReadService.GetUniqueTagsByAppId(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetTagsByAppId", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, resp, http.StatusInternalServerError)
		return
	}
	resp.AppReleaseTagNames = appTags

	prodEnvExists, err := handler.imageTaggingService.GetProdEnvByCdPipelineId(pipelineId)
	resp.TagsEdiatable = prodEnvExists
	resp.HideImageTaggingHardDelete = handler.imageTaggingService.IsHardDeleteHidden()
	if err != nil {
		handler.Logger.Errorw("service err, GetProdEnvFromParentAndLinkedWorkflow", "err", err, "cdPipelineId", pipelineId)
		common.WriteJsonResp(w, err, resp, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetPrePostDeploymentLogs(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	workflowId, err := strconv.Atoi(vars["workflowId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	followLogs := true
	if ok := r.URL.Query().Has("followLogs"); ok {
		followLogsStr := r.URL.Query().Get("followLogs")
		follow, err := strconv.ParseBool(followLogsStr)
		if err != nil {
			common.WriteJsonResp(w, err, "followLogs is not a valid bool", http.StatusBadRequest)
			return
		}
		followLogs = follow
	}
	handler.Logger.Infow("request payload, GetPrePostDeploymentLogs", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "workflowId", workflowId)

	// RBAC CHECK
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC CHECK

	logsReader, cleanUp, err := handler.cdHandlerService.GetRunningWorkflowLogs(environmentId, pipelineId, workflowId, followLogs)
	if err != nil {
		handler.Logger.Errorw("service err, GetPrePostDeploymentLogs", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "workflowId", workflowId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	lastSeenMsgId := -1
	lastEventId := r.Header.Get("Last-Event-ID")
	if len(lastEventId) > 0 {
		lastSeenMsgId, err = strconv.Atoi(lastEventId)
		if err != nil {
			handler.Logger.Errorw("request err, GetPrePostDeploymentLogs", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "workflowId", workflowId, "lastEventId", lastEventId)
			common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := w.(http.CloseNotifier); ok {
		go func(done <-chan struct{}, closed <-chan bool) {
			select {
			case <-done:
			case <-closed:
				cancel()
			}
		}(ctx.Done(), cn.CloseNotify())
	}
	defer cancel()
	defer func() {
		if cleanUp != nil {
			cleanUp()
		}
	}()
	handler.streamOutput(w, logsReader, lastSeenMsgId)
}

func (handler *PipelineConfigRestHandlerImpl) FetchCdWorkflowDetails(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	buildId, err := strconv.Atoi(vars["workflowRunnerId"])
	if err != nil || buildId == 0 {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, FetchCdWorkflowDetails", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "buildId", buildId)

	// RBAC CHECK
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC CHECK

	resp, err := handler.cdHandler.FetchCdWorkflowDetails(appId, environmentId, pipelineId, buildId)
	if err != nil {
		handler.Logger.Errorw("service err, FetchCdWorkflowDetails", "err", err, "appId", appId, "environmentId", environmentId, "pipelineId", pipelineId, "buildId", buildId)
		if util.IsErrNoRows(err) {
			err = &util.ApiError{Code: "404", HttpStatusCode: http.StatusNotFound, UserMessage: "no workflow found"}
			common.WriteJsonResp(w, err, nil, http.StatusOK)
		} else {
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		}
		return
	}
	common.WriteJsonResp(w, err, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) DownloadArtifacts(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	buildId, err := strconv.Atoi(vars["workflowRunnerId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, DownloadArtifacts", "err", err, "appId", appId, "pipelineId", pipelineId, "buildId", buildId)

	// RBAC CHECK
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetAppRBACByAppIdAndPipelineId(appId, pipelineId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC CHECK

	file, err := handler.cdHandlerService.DownloadCdWorkflowArtifacts(buildId)
	defer file.Close()

	if err != nil {
		handler.Logger.Errorw("service err, DownloadArtifacts", "err", err, "appId", appId, "pipelineId", pipelineId, "buildId", buildId)
		if util.IsErrNoRows(err) {
			err = &util.ApiError{Code: "404", HttpStatusCode: 200, UserMessage: "no workflow found"}
			common.WriteJsonResp(w, err, nil, http.StatusOK)
		} else {
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Itoa(buildId)+".zip")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", r.Header.Get("Content-Length"))
	_, err = io.Copy(w, file)
	if err != nil {
		handler.Logger.Errorw("service err, DownloadArtifacts", "err", err, "appId", appId, "pipelineId", pipelineId, "buildId", buildId)
	}
}

func (handler *PipelineConfigRestHandlerImpl) GetStageStatus(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetStageStatus", "err", err, "appId", appId, "pipelineId", pipelineId)

	// RBAC CHECK
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetAppRBACByAppIdAndPipelineId(appId, pipelineId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC CHECK

	resp, err := handler.cdHandler.FetchCdPrePostStageStatus(pipelineId)
	if err != nil {
		handler.Logger.Errorw("service err, GetStageStatus", "err", err, "appId", appId, "pipelineId", pipelineId)
		if util.IsErrNoRows(err) {
			err = &util.ApiError{Code: "404", HttpStatusCode: 200, UserMessage: "no status found"}
			common.WriteJsonResp(w, err, nil, http.StatusOK)
		} else {
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		}
		return
	}
	common.WriteJsonResp(w, err, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetConfigmapSecretsForDeploymentStages(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetConfigmapSecretsForDeploymentStages", "err", err, "pipelineId", pipelineId)
	deploymentPipeline, err := handler.pipelineBuilder.FindPipelineById(pipelineId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	// FIXME: add RBAC
	resp, err := handler.pipelineBuilder.FetchConfigmapSecretsForCdStages(deploymentPipeline.AppId, deploymentPipeline.EnvironmentId)
	if err != nil {
		handler.Logger.Errorw("service err, GetConfigmapSecretsForDeploymentStages", "err", err, "pipelineId", pipelineId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetCdPipelineById(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	version := "v1"
	if strings.Contains(r.URL.Path, "v2") {
		version = "v2"
	}
	handler.Logger.Infow("request payload, GetCdPipelineById", "err", err, "appId", appId, "pipelineId", pipelineId)
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	envObject := handler.enforcerUtil.GetEnvRBACNameByCdPipelineIdAndEnvId(pipelineId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionUpdate, envObject); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	cdResp, err := handler.pipelineBuilder.GetCdPipelineByIdResolved(pipelineId, version)
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelineByIdResolved", "appId", appId, "pipelineId", pipelineId, "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, cdResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) CancelStage(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	workflowRunnerId, err := strconv.Atoi(vars["workflowRunnerId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	cdPipeline, err := handler.pipelineRepository.FindById(pipelineId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	var forceAbort bool
	forceAbortQueryParam := r.URL.Query().Get("forceAbort")
	if len(forceAbortQueryParam) > 0 {
		forceAbort, err = strconv.ParseBool(forceAbortQueryParam)
		if err != nil {
			handler.Logger.Errorw("request err, CancelWorkflow", "err", err)
			common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
			return
		}
	}
	handler.Logger.Infow("request payload, CancelStage", "pipelineId", pipelineId, "workflowRunnerId", workflowRunnerId)

	// RBAC
	token := r.Header.Get("token")
	object := handler.enforcerUtil.GetAppRBACNameByAppId(cdPipeline.AppId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionTrigger, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC

	resp, err := handler.cdHandlerService.CancelStage(workflowRunnerId, forceAbort, userId)
	if err != nil {
		handler.Logger.Errorw("service err, CancelStage", "err", err, "pipelineId", pipelineId, "workflowRunnerId", workflowRunnerId)
		if util.IsErrNoRows(err) {
			common.WriteJsonResp(w, err, nil, http.StatusNotFound)
		} else {
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		}
		return
	}
	common.WriteJsonResp(w, err, resp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetDeploymentPipelineStrategy(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetDeploymentPipelineStrategy", "appId", appId)
	// RBAC
	object := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC

	result, err := handler.pipelineBuilder.FetchCDPipelineStrategy(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetDeploymentPipelineStrategy", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	common.WriteJsonResp(w, err, result, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetDefaultDeploymentPipelineStrategy(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, GetDefaultDeploymentPipelineStrategy", "appId", appId, "envId", envId)
	// RBAC
	object := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC

	result, err := handler.pipelineBuilder.FetchDefaultCDPipelineStrategy(appId, envId)
	if err != nil {
		handler.Logger.Errorw("service err, GetDefaultDeploymentPipelineStrategy", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	common.WriteJsonResp(w, err, result, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) EnvConfigOverrideCreateNamespace(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	environmentId, err := strconv.Atoi(vars["environmentId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(r.Body)
	var envConfigProperties pipelineBean.EnvironmentProperties
	err = decoder.Decode(&envConfigProperties)
	envConfigProperties.UserId = userId
	envConfigProperties.EnvironmentId = environmentId
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, EnvConfigOverrideCreateNamespace", "appId", appId, "environmentId", environmentId, "payload", envConfigProperties)
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	object := handler.enforcerUtil.GetAppRBACByAppNameAndEnvId(app.AppName, environmentId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionCreate, object); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	createResp, err := handler.propertiesConfigService.CreateEnvironmentPropertiesWithNamespace(appId, &envConfigProperties)
	if err != nil {
		handler.Logger.Errorw("service err, EnvConfigOverrideCreateNamespace", "err", err, "appId", appId, "environmentId", environmentId, "payload", envConfigProperties)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, createResp, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) IsReadyToTrigger(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	pipelineId, err := strconv.Atoi(vars["pipelineId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Infow("request payload, IsReadyToTrigger", "appId", appId, "envId", envId, "pipelineId", pipelineId)
	// RBAC
	object := handler.enforcerUtil.GetAppRBACNameByAppId(appId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	object = handler.enforcerUtil.GetEnvRBACNameByAppId(appId, envId)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionGet, object); !ok {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusForbidden)
		return
	}
	// RBAC

	result, err := handler.chartService.IsReadyToTrigger(appId, envId, pipelineId)
	if err != nil {
		handler.Logger.Errorw("service err, IsReadyToTrigger", "err", err, "appId", appId, "envId", envId, "pipelineId", pipelineId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, result, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) UpgradeForAllApps(w http.ResponseWriter, r *http.Request) {
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	chartRefId, err := strconv.Atoi(vars["chartRefId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var chartUpgradeRequest bean3.ChartUpgradeRequest
	err = decoder.Decode(&chartUpgradeRequest)
	if err != nil {
		handler.Logger.Errorw("request err, UpgradeForAllApps", "err", err, "payload", chartUpgradeRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	chartUpgradeRequest.ChartRefId = chartRefId
	chartUpgradeRequest.UserId = userId
	handler.Logger.Infow("request payload, UpgradeForAllApps", "payload", chartUpgradeRequest)
	token := r.Header.Get("token")
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, "*/*"); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}
	if ok := handler.enforcer.Enforce(token, casbin.ResourceEnvironment, casbin.ActionCreate, "*/*"); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	newAppOverride, _, err := handler.chartRefService.GetAppOverrideForDefaultTemplate(chartUpgradeRequest.ChartRefId)
	if err != nil {
		handler.Logger.Errorw("service err, UpgradeForAllApps", "err", err, "payload", chartUpgradeRequest)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := w.(http.CloseNotifier); ok {
		go func(done <-chan struct{}, closed <-chan bool) {
			select {
			case <-done:
			case <-closed:
				cancel()
			}
		}(ctx.Done(), cn.CloseNotify())
	}

	var appIds []int
	if chartUpgradeRequest.All || len(chartUpgradeRequest.AppIds) == 0 {
		apps, err := handler.pipelineBuilder.GetAppList()
		if err != nil {
			handler.Logger.Errorw("service err, UpgradeForAllApps", "err", err, "payload", chartUpgradeRequest)
			common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
			return
		}
		for _, app := range apps {
			appIds = append(appIds, app.Id)
		}
	} else {
		appIds = chartUpgradeRequest.AppIds
	}
	response := make(map[string][]map[string]string)
	var failedIds []map[string]string
	for _, appId := range appIds {
		appResponse := make(map[string]string)
		template, err := handler.chartReadService.GetByAppIdAndChartRefId(appId, chartRefId)
		if err != nil && pg.ErrNoRows != err {
			handler.Logger.Errorw("err in checking weather exist or not, skip for upgrade", "err", err, "payload", chartUpgradeRequest)
			appResponse["appId"] = strconv.Itoa(appId)
			appResponse["message"] = "err in checking weather exist or not, skip for upgrade"
			failedIds = append(failedIds, appResponse)
			continue
		}
		if template != nil && template.Id > 0 {
			handler.Logger.Warnw("this ref chart already configured for this app, skip for upgrade", "payload", chartUpgradeRequest)
			appResponse["appId"] = strconv.Itoa(appId)
			appResponse["message"] = "this ref chart already configured for this app, skip for upgrade"
			failedIds = append(failedIds, appResponse)
			continue
		}
		flag, err := handler.chartService.UpgradeForApp(appId, chartRefId, newAppOverride, userId, ctx)
		if err != nil {
			handler.Logger.Errorw("service err, UpdateCiTemplate", "err", err, "payload", chartUpgradeRequest)
			appResponse["appId"] = strconv.Itoa(appId)
			appResponse["message"] = err.Error()
			failedIds = append(failedIds, appResponse)
		} else if flag == false {
			handler.Logger.Debugw("unable to upgrade for app", "appId", appId, "payload", chartUpgradeRequest)
			appResponse["appId"] = strconv.Itoa(appId)
			appResponse["message"] = "no error found, but failed to upgrade"
			failedIds = append(failedIds, appResponse)
		}

	}
	response["failed"] = failedIds
	common.WriteJsonResp(w, err, response, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetCdPipelinesByEnvironment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := r.Header.Get("token")
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetCdPipelines", "err", err, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	v := r.URL.Query()
	appIdsString := v.Get("appIds")
	var appIds []int
	if len(appIdsString) > 0 {
		appIdsSlices := strings.Split(appIdsString, ",")
		for _, appId := range appIdsSlices {
			id, err := strconv.Atoi(appId)
			if err != nil {
				common.WriteJsonResp(w, err, "please provide valid appIds", http.StatusBadRequest)
				return
			}
			appIds = append(appIds, id)
		}
	}
	var appGroupId int
	appGroupIdStr := v.Get("appGroupId")
	if len(appGroupIdStr) > 0 {
		appGroupId, err = strconv.Atoi(appGroupIdStr)
		if err != nil {
			common.WriteJsonResp(w, err, "please provide valid appGroupId", http.StatusBadRequest)
			return
		}
	}

	request := resourceGroup2.ResourceGroupingRequest{
		ParentResourceId:  envId,
		ResourceGroupId:   appGroupId,
		ResourceGroupType: resourceGroup2.APP_GROUP,
		ResourceIds:       appIds,
		CheckAuthBatch:    handler.checkAuthBatch,
		UserId:            userId,
		Ctx:               r.Context(),
	}
	_, span := otel.Tracer("orchestrator").Start(r.Context(), "cdHandler.FetchCdPipelinesForResourceGrouping")
	results, err := handler.pipelineBuilder.GetCdPipelinesByEnvironment(request, token)
	span.End()
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelines", "err", err, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, results, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetCdPipelinesByEnvironmentMin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	envId, err := strconv.Atoi(vars["envId"])
	if err != nil {
		handler.Logger.Errorw("request err, GetCdPipelines", "err", err, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	v := r.URL.Query()
	appIdsString := v.Get("appIds")
	var appIds []int
	if len(appIdsString) > 0 {
		appIdsSlices := strings.Split(appIdsString, ",")
		for _, appId := range appIdsSlices {
			id, err := strconv.Atoi(appId)
			if err != nil {
				common.WriteJsonResp(w, err, "please provide valid appIds", http.StatusBadRequest)
				return
			}
			appIds = append(appIds, id)
		}
	}
	var appGroupId int
	appGroupIdStr := v.Get("appGroupId")
	if len(appGroupIdStr) > 0 {
		appGroupId, err = strconv.Atoi(appGroupIdStr)
		if err != nil {
			common.WriteJsonResp(w, err, "please provide valid appGroupId", http.StatusBadRequest)
			return
		}
	}

	request := resourceGroup2.ResourceGroupingRequest{
		ParentResourceId:  envId,
		ResourceGroupId:   appGroupId,
		ResourceGroupType: resourceGroup2.APP_GROUP,
		ResourceIds:       appIds,
		CheckAuthBatch:    handler.checkAuthBatch,
		UserId:            userId,
		Ctx:               r.Context(),
	}

	_, span := otel.Tracer("orchestrator").Start(r.Context(), "cdHandler.FetchCdPipelinesForResourceGrouping")
	results, err := handler.pipelineBuilder.GetCdPipelinesByEnvironmentMin(request, token)
	span.End()
	if err != nil {
		handler.Logger.Errorw("service err, GetCdPipelines", "err", err, "envId", envId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, results, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) checkAuthBatch(token string, appObject []string, envObject []string) (map[string]bool, map[string]bool) {
	var appResult map[string]bool
	var envResult map[string]bool
	if len(appObject) > 0 {
		appResult = handler.enforcer.EnforceInBatch(token, casbin.ResourceApplications, casbin.ActionGet, appObject)
	}
	if len(envObject) > 0 {
		envResult = handler.enforcer.EnforceInBatch(token, casbin.ResourceEnvironment, casbin.ActionGet, envObject)
	}
	return appResult, envResult
}

func (handler *PipelineConfigRestHandlerImpl) SaveGitOpsConfiguration(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var appGitOpsConfigRequest devtronAppGitOpConfigBean.AppGitOpsConfigRequest
	err = decoder.Decode(&appGitOpsConfigRequest)
	if err != nil {
		handler.Logger.Errorw("request err, SaveGitOpsConfiguration", "err", err, "payload", appGitOpsConfigRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	appGitOpsConfigRequest.UserId = userId

	handler.Logger.Infow("request payload, SaveGitOpsConfiguration", "payload", appGitOpsConfigRequest)
	err = handler.validator.Struct(appGitOpsConfigRequest)
	if err != nil {
		handler.Logger.Errorw("validation err, ConfigureDeploymentTemplateForApp", "err", err, "payload", appGitOpsConfigRequest)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	token := r.Header.Get("token")
	app, err := handler.pipelineBuilder.GetApp(appGitOpsConfigRequest.AppId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	ctx := r.Context()

	_, span := otel.Tracer("orchestrator").Start(ctx, "chartService.SaveAppLevelGitOpsConfiguration")
	err = handler.devtronAppGitOpConfigService.SaveAppLevelGitOpsConfiguration(&appGitOpsConfigRequest, app.AppName, ctx)
	span.End()
	if err != nil {
		handler.Logger.Errorw("service err, SaveAppLevelGitOpsConfiguration", "err", err, "request", appGitOpsConfigRequest)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, appGitOpsConfigRequest, http.StatusOK)
}

func (handler *PipelineConfigRestHandlerImpl) GetGitOpsConfiguration(w http.ResponseWriter, r *http.Request) {

	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	vars := mux.Vars(r)
	appId, err := strconv.Atoi(vars["appId"])
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	app, err := handler.pipelineBuilder.GetApp(appId)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	resourceName := handler.enforcerUtil.GetAppRBACName(app.AppName)
	if ok := handler.enforcer.Enforce(token, casbin.ResourceApplications, casbin.ActionCreate, resourceName); !ok {
		common.WriteJsonResp(w, fmt.Errorf("unauthorized user"), "Unauthorized User", http.StatusForbidden)
		return
	}

	appGitOpsConfig, err := handler.devtronAppGitOpConfigService.GetAppLevelGitOpsConfiguration(appId)
	if err != nil {
		handler.Logger.Errorw("service err, GetAppLevelGitOpsConfiguration", "err", err, "appId", appId)
		common.WriteJsonResp(w, err, err, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, appGitOpsConfig, http.StatusOK)
}

// this is being used for getting all cdPipelines in the case of changing the source from any [except] -> external-ci
func (handler *PipelineConfigRestHandlerImpl) getCdPipelinesForCdPatchRbac(deploymentPipeline *bean.CDPipelineConfigObject) (cdPipelines []*pipelineConfig.Pipeline, err error) {
	componentId, componentType := deploymentPipeline.PatchSourceInfo()
	// the appWorkflowId can be taken from patchRequest.AppWorkflowId but doing this can make 2 sources of truth to find the workflow
	sourceAppWorkflowMapping, err := handler.appWorkflowService.FindWFMappingByComponent(componentType, componentId)
	if err != nil {
		handler.Logger.Errorw("error in finding the appWorkflowMapping using componentId and componentType", "componentType", componentType, "componentId", componentId, "err", err)
		return nil, err
	}
	cdPipelineWFMappings, err := handler.appWorkflowService.FindWFCDMappingsByWorkflowId(sourceAppWorkflowMapping.AppWorkflowId)
	if err != nil {
		handler.Logger.Errorw("error in finding the appWorkflowMappings of cd pipeline for an appWorkflow", "appWorkflowId", sourceAppWorkflowMapping.AppWorkflowId, "err", err)
		return cdPipelines, err
	}
	if len(cdPipelineWFMappings) == 0 {
		return
	}

	cdPipelineIds := make([]int, 0, len(cdPipelineWFMappings))
	for _, cdWfMapping := range cdPipelineWFMappings {
		cdPipelineIds = append(cdPipelineIds, cdWfMapping.ComponentId)
	}
	return handler.pipelineRepository.FindByIdsIn(cdPipelineIds)
}

func (handler *PipelineConfigRestHandlerImpl) ValidateExternalAppLinkRequest(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := handler.userAuthService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var request pipelineBean.MigrateReleaseValidationRequest
	err = decoder.Decode(&request)
	if err != nil {
		handler.Logger.Errorw("request err, request", "err", err, "payload", request)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	handler.Logger.Debugw("request payload, ValidateExternalAppLinkRequest", "payload", request)
	token := r.Header.Get("token")
	if ok := handler.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionUpdate, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	ctx := r.Context()
	if request.DeploymentAppType == util.PIPELINE_DEPLOYMENT_TYPE_ACD {
		response := handler.pipelineBuilder.ValidateLinkExternalArgoCDRequest(&request)
		common.WriteJsonResp(w, err, response, http.StatusOK)
		return
	} else if request.DeploymentAppType == util.PIPELINE_DEPLOYMENT_TYPE_HELM {
		response := handler.pipelineBuilder.ValidateLinkHelmAppRequest(ctx, &request)
		common.WriteJsonResp(w, err, response, http.StatusOK)
		return
		// handle helm deployment types
	} else if request.DeploymentAppType == util.PIPELINE_DEPLOYMENT_TYPE_FLUX {
		response := handler.pipelineBuilder.ValidateLinkFluxAppRequest(ctx, &request)
		common.WriteJsonResp(w, err, response, http.StatusOK)
		return
		// handle helm deployment types
	}
	common.WriteJsonResp(w, errors.New("invalid deployment app type in request"), nil, http.StatusBadRequest)
	return
}
