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

package status

import (
	"context"
	"fmt"
	util2 "github.com/devtron-labs/devtron/internal/util"
	bean4 "github.com/devtron-labs/devtron/pkg/fluxApplication/bean"
	util "github.com/devtron-labs/devtron/util/event"
	"time"

	bean2 "github.com/devtron-labs/devtron/api/bean"
	"github.com/devtron-labs/devtron/api/helm-app/service/bean"
	"github.com/devtron-labs/devtron/client/argocdServer"
	appRepository "github.com/devtron-labs/devtron/internal/sql/repository/app"
	"github.com/devtron-labs/devtron/internal/sql/repository/chartConfig"
	"github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig"
	"github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig/adapter/cdWorkflow"
	"github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig/bean/timelineStatus"
	cdWorkflow2 "github.com/devtron-labs/devtron/internal/sql/repository/pipelineConfig/bean/workflow/cdWorkflow"
	"github.com/devtron-labs/devtron/pkg/app"
	"github.com/devtron-labs/devtron/pkg/app/status"
	app_status "github.com/devtron-labs/devtron/pkg/appStatus"
	installedAppReader "github.com/devtron-labs/devtron/pkg/appStore/installedApp/read"
	installedAppReadBean "github.com/devtron-labs/devtron/pkg/appStore/installedApp/read/bean"
	repository3 "github.com/devtron-labs/devtron/pkg/appStore/installedApp/repository"
	repository2 "github.com/devtron-labs/devtron/pkg/cluster/environment/repository"
	common2 "github.com/devtron-labs/devtron/pkg/deployment/common"
	bean3 "github.com/devtron-labs/devtron/pkg/deployment/trigger/devtronApps/bean"
	"github.com/devtron-labs/devtron/pkg/eventProcessor/out"
	"github.com/devtron-labs/devtron/pkg/pipeline/types"
	"github.com/devtron-labs/devtron/pkg/sql"
	"github.com/devtron-labs/devtron/pkg/workflow/cd"
	"github.com/devtron-labs/devtron/pkg/workflow/dag"
	util3 "github.com/devtron-labs/devtron/util"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"k8s.io/utils/strings/slices"
)

type WorkflowStatusService interface {
	CheckHelmAppStatusPeriodicallyAndUpdateInDb(helmPipelineStatusCheckEligibleTime int,
		getPipelineDeployedWithinHours int) error

	UpdatePipelineTimelineAndStatusByLiveApplicationFetch(triggerContext bean3.TriggerContext, pipeline *pipelineConfig.Pipeline, installedApp *installedAppReadBean.InstalledAppMin, userId int32) (error, bool)

	CheckAndSendArgoPipelineStatusSyncEventIfNeeded(pipelineId int, installedAppVersionId int,
		userId int32, isAppStoreApplication bool)

	CheckArgoPipelineTimelineStatusPeriodicallyAndUpdateInDb(pendingSinceSeconds int, timeForDegradation int) error

	CheckArgoAppStatusPeriodicallyAndUpdateInDb(getPipelineDeployedBeforeMinutes int, getPipelineDeployedWithinHours int) error

	CheckFluxAppStatusPeriodicallyAndUpdateInDb(fluxPipelineStatusCheckEligibleTime int, getPipelineDeployedWithinHours int, cdPipelineTimeoutDuration int) error
}

type WorkflowStatusServiceImpl struct {
	logger                          *zap.SugaredLogger
	workflowDagExecutor             dag.WorkflowDagExecutor
	pipelineStatusTimelineService   status.PipelineStatusTimelineService
	appService                      app.AppService
	config                          *types.CdConfig
	appStatusService                app_status.AppStatusService
	acdConfig                       *argocdServer.ACDConfig
	AppConfig                       *app.AppServiceConfig
	pipelineStatusSyncDetailService status.PipelineStatusSyncDetailService
	argocdClientWrapperService      argocdServer.ArgoClientWrapperService
	cdPipelineEventPublishService   out.CDPipelineEventPublishService

	cdWorkflowRepository                 pipelineConfig.CdWorkflowRepository
	pipelineOverrideRepository           chartConfig.PipelineOverrideRepository
	installedAppVersionHistoryRepository repository3.InstalledAppVersionHistoryRepository
	appRepository                        appRepository.AppRepository
	envRepository                        repository2.EnvironmentRepository
	installedAppRepository               repository3.InstalledAppRepository
	installedAppReadService              installedAppReader.InstalledAppReadService
	pipelineStatusTimelineRepository     pipelineConfig.PipelineStatusTimelineRepository
	pipelineRepository                   pipelineConfig.PipelineRepository
	appListingService                    app.AppListingService
	deploymentConfigService              common2.DeploymentConfigService
	cdWorkflowRunnerService              cd.CdWorkflowRunnerService
	deploymentEventHandler               app.DeploymentEventHandler
}

func NewWorkflowStatusServiceImpl(logger *zap.SugaredLogger,
	workflowDagExecutor dag.WorkflowDagExecutor,
	pipelineStatusTimelineService status.PipelineStatusTimelineService,
	appService app.AppService, appStatusService app_status.AppStatusService,
	acdConfig *argocdServer.ACDConfig, AppConfig *app.AppServiceConfig,
	pipelineStatusSyncDetailService status.PipelineStatusSyncDetailService,
	argocdClientWrapperService argocdServer.ArgoClientWrapperService,
	cdPipelineEventPublishService out.CDPipelineEventPublishService,
	cdWorkflowRepository pipelineConfig.CdWorkflowRepository,
	pipelineOverrideRepository chartConfig.PipelineOverrideRepository,
	installedAppVersionHistoryRepository repository3.InstalledAppVersionHistoryRepository,
	appRepository appRepository.AppRepository,
	envRepository repository2.EnvironmentRepository,
	installedAppRepository repository3.InstalledAppRepository,
	installedAppReadService installedAppReader.InstalledAppReadService,
	pipelineStatusTimelineRepository pipelineConfig.PipelineStatusTimelineRepository,
	pipelineRepository pipelineConfig.PipelineRepository,
	appListingService app.AppListingService,
	deploymentConfigService common2.DeploymentConfigService,
	cdWorkflowRunnerService cd.CdWorkflowRunnerService,
	deploymentEventHandler app.DeploymentEventHandler) (*WorkflowStatusServiceImpl, error) {
	impl := &WorkflowStatusServiceImpl{
		logger:                               logger,
		workflowDagExecutor:                  workflowDagExecutor,
		pipelineStatusTimelineService:        pipelineStatusTimelineService,
		appService:                           appService,
		appStatusService:                     appStatusService,
		acdConfig:                            acdConfig,
		AppConfig:                            AppConfig,
		pipelineStatusSyncDetailService:      pipelineStatusSyncDetailService,
		argocdClientWrapperService:           argocdClientWrapperService,
		cdPipelineEventPublishService:        cdPipelineEventPublishService,
		cdWorkflowRepository:                 cdWorkflowRepository,
		pipelineOverrideRepository:           pipelineOverrideRepository,
		installedAppVersionHistoryRepository: installedAppVersionHistoryRepository,
		appRepository:                        appRepository,
		envRepository:                        envRepository,
		installedAppRepository:               installedAppRepository,
		installedAppReadService:              installedAppReadService,
		pipelineStatusTimelineRepository:     pipelineStatusTimelineRepository,
		pipelineRepository:                   pipelineRepository,
		appListingService:                    appListingService,
		deploymentConfigService:              deploymentConfigService,
		cdWorkflowRunnerService:              cdWorkflowRunnerService,
		deploymentEventHandler:               deploymentEventHandler,
	}
	config, err := types.GetCdConfig()
	if err != nil {
		return nil, err
	}
	impl.config = config
	return impl, nil
}

func (impl *WorkflowStatusServiceImpl) CheckHelmAppStatusPeriodicallyAndUpdateInDb(helmPipelineStatusCheckEligibleTime int,
	getPipelineDeployedWithinHours int) error {
	wfrList, err := impl.cdWorkflowRepository.GetLatestTriggersOfPipelinesStuckInNonTerminalStatuses(getPipelineDeployedWithinHours, util2.PIPELINE_DEPLOYMENT_TYPE_HELM)
	if err != nil {
		impl.logger.Errorw("error in getting latest triggers of helm pipelines which are stuck in non terminal statuses", "err", err)
		return err
	}
	impl.logger.Debugw("checking helm app status for non terminal deployment triggers", "wfrList", wfrList, "number of wfr", len(wfrList))
	for _, wfr := range wfrList {
		if time.Now().Sub(wfr.StartedOn) <= time.Duration(helmPipelineStatusCheckEligibleTime)*time.Second {
			// if wfr is updated within configured time then do not include for this cron cycle
			continue
		}
		appIdentifier := &bean.AppIdentifier{
			ClusterId:   wfr.CdWorkflow.Pipeline.Environment.ClusterId,
			Namespace:   wfr.CdWorkflow.Pipeline.Environment.Namespace,
			ReleaseName: wfr.CdWorkflow.Pipeline.DeploymentAppName,
		}
		if isWfrUpdated := impl.workflowDagExecutor.UpdateWorkflowRunnerStatusForDeployment(appIdentifier, wfr, true); !isWfrUpdated {
			continue
		}
		wfr.UpdatedBy = 1
		wfr.UpdatedOn = time.Now()

		pipelineOverride, err := impl.pipelineOverrideRepository.FindLatestByCdWorkflowId(wfr.CdWorkflowId)
		if err != nil {
			impl.logger.Errorw("error in getting latest pipeline override by cdWorkflowId", "err", err, "cdWorkflowId", wfr.CdWorkflowId)
			return err
		}

		if wfr.Status == cdWorkflow2.WorkflowFailed {
			err = impl.pipelineStatusTimelineService.MarkPipelineStatusTimelineSuperseded(wfr.RefCdWorkflowRunnerId)
			if err != nil {
				impl.logger.Errorw("error updating CdPipelineStatusTimeline", "err", err)
				return err
			}
			impl.deploymentEventHandler.WriteCDNotificationEventAsync(pipelineOverride.Pipeline.AppId, pipelineOverride.Pipeline.EnvironmentId, pipelineOverride, util.Fail)
		}
		err = impl.cdWorkflowRunnerService.UpdateCdWorkflowRunnerWithStage(wfr)
		if err != nil {
			impl.logger.Errorw("error on update cd workflow runner", "wfr", wfr, "err", err)
			return err
		}
		appId := wfr.CdWorkflow.Pipeline.AppId
		envId := wfr.CdWorkflow.Pipeline.EnvironmentId
		envDeploymentConfig, err := impl.deploymentConfigService.GetConfigForDevtronApps(appId, envId)
		if err != nil {
			impl.logger.Errorw("error in fetching environment deployment config by appId and envId", "appId", appId, "envId", envId, "err", err)
			return err
		}
		if slices.Contains(cdWorkflow2.WfrTerminalStatusList, wfr.Status) {
			util3.TriggerCDMetrics(cdWorkflow.GetTriggerMetricsFromRunnerObj(wfr, envDeploymentConfig), impl.config.ExposeCDMetrics)
		}

		impl.logger.Infow("updated workflow runner status for helm app", "wfr", wfr)
		if wfr.Status == cdWorkflow2.WorkflowSucceeded {
			impl.deploymentEventHandler.WriteCDNotificationEventAsync(pipelineOverride.Pipeline.AppId, pipelineOverride.Pipeline.EnvironmentId, pipelineOverride, util.Success)
			err = impl.workflowDagExecutor.HandleDeploymentSuccessEvent(bean3.TriggerContext{}, pipelineOverride)
			if err != nil {
				impl.logger.Errorw("error on handling deployment success event", "wfr", wfr, "err", err)
				return err
			}
		}
	}
	return nil
}

func (impl *WorkflowStatusServiceImpl) UpdatePipelineTimelineAndStatusByLiveApplicationFetch(triggerContext bean3.TriggerContext,
	pipeline *pipelineConfig.Pipeline, installedApp *installedAppReadBean.InstalledAppMin, userId int32) (error, bool) {
	isTimelineUpdated := false
	isSucceeded := false
	var pipelineOverride *chartConfig.PipelineOverride
	if pipeline != nil {
		isAppStore := false
		cdWfr, err := impl.cdWorkflowRepository.FindLatestByPipelineIdAndRunnerType(pipeline.Id, bean2.CD_WORKFLOW_TYPE_DEPLOY)
		if err != nil {
			impl.logger.Errorw("error in getting latest cdWfr by cdPipelineId", "err", err, "pipelineId", pipeline.Id)
			return nil, isTimelineUpdated
		}
		impl.logger.Debugw("ARGO_PIPELINE_STATUS_UPDATE_REQ", "stage", "checkingDeploymentStatus", "argoAppName", pipeline, "cdWfr", cdWfr)
		if util3.IsTerminalRunnerStatus(cdWfr.Status) {
			// drop event
			return nil, isTimelineUpdated
		}

		// this should only be called when we have git-ops configured
		// try fetching status from argo cd
		dc, err := impl.deploymentConfigService.GetConfigForDevtronApps(pipeline.AppId, pipeline.EnvironmentId)
		if err != nil {
			impl.logger.Errorw("error, GetConfigForDevtronApps", "appId", pipeline.AppId, "environmentId", pipeline.EnvironmentId, "err", err)
			return nil, isTimelineUpdated
		}

		if impl.acdConfig.IsManualSyncEnabled() && dc.IsArgoAppSyncAndRefreshSupported() {
			// if manual sync check for application sync status
			isArgoAppSynced := impl.pipelineStatusTimelineService.GetArgoAppSyncStatus(cdWfr.Id)
			if !isArgoAppSynced {
				return nil, isTimelineUpdated
			}
		}

		applicationObjectClusterId := dc.GetApplicationObjectClusterId()
		applicationObjectNamespace := dc.GetApplicationObjectNamespace()
		app, err := impl.argocdClientWrapperService.GetArgoAppByNameWithK8sClient(context.Background(), applicationObjectClusterId, applicationObjectNamespace, pipeline.DeploymentAppName)
		if err != nil {
			impl.logger.Errorw("error in getting acd application", "err", err, "argoAppName", pipeline)
			// updating cdWfr status
			cdWfr.Status = cdWorkflow2.WorkflowUnableToFetchState
			cdWfr.UpdatedOn = time.Now()
			cdWfr.UpdatedBy = 1
			err = impl.cdWorkflowRunnerService.UpdateCdWorkflowRunnerWithStage(&cdWfr)
			if err != nil {
				impl.logger.Errorw("error on update cd workflow runner", "cdWfr", cdWfr, "err", err)
				return err, isTimelineUpdated
			}
			// creating cd pipeline status timeline
			timeline := &pipelineConfig.PipelineStatusTimeline{
				CdWorkflowRunnerId: cdWfr.Id,
				Status:             timelineStatus.TIMELINE_STATUS_UNABLE_TO_FETCH_STATUS,
				StatusDetail:       "Failed to connect to Argo CD to fetch deployment status.",
				StatusTime:         time.Now(),
				AuditLog: sql.AuditLog{
					CreatedBy: userId,
					CreatedOn: time.Now(),
					UpdatedBy: userId,
					UpdatedOn: time.Now(),
				},
			}
			err = impl.pipelineStatusTimelineService.SaveTimeline(timeline, nil)
			if err != nil {
				impl.logger.Errorw("error in creating timeline status for app", "err", err, "timeline", timeline)
				return err, isTimelineUpdated
			}
		} else {
			if app == nil {
				impl.logger.Errorw("found empty argo application object", "appName", pipeline.DeploymentAppName)
				return fmt.Errorf("found empty argo application object"), isTimelineUpdated
			}
			isSucceeded, isTimelineUpdated, pipelineOverride, err = impl.appService.UpdateDeploymentStatusForGitOpsPipelines(app, applicationObjectClusterId, time.Now(), isAppStore)
			if err != nil {
				impl.logger.Errorw("error in updating deployment status for gitOps cd pipelines", "app", app, "err", err)
				return err, isTimelineUpdated
			}

			appStatus, err := impl.appService.ComputeAppstatus(pipeline.AppId, pipeline.EnvironmentId, app.Status.Health.Status)
			if err != nil {
				impl.logger.Errorw("error in checking if last release is stop type", "err", err, pipeline.AppId, "envId", pipeline.EnvironmentId)
				return err, isTimelineUpdated
			}

			err = impl.appStatusService.UpdateStatusWithAppIdEnvId(pipeline.AppId, pipeline.EnvironmentId, appStatus)
			if err != nil {
				impl.logger.Errorw("error occurred while updating app-status for cd pipeline", "err", err, "appId", pipeline.AppId, "envId", pipeline.EnvironmentId)
				impl.logger.Debugw("ignoring the error, UpdateStatusWithAppIdEnvId", "err", err, "appId", pipeline.AppId, "envId", pipeline.EnvironmentId)
			}
		}
		if isSucceeded {
			// handling deployment success event
			err = impl.workflowDagExecutor.HandleDeploymentSuccessEvent(triggerContext, pipelineOverride)
			if err != nil {
				impl.logger.Errorw("error in handling deployment success event", "pipelineOverride", pipelineOverride, "err", err)
				return err, isTimelineUpdated
			}
		}
	} else if installedApp != nil {
		isAppStore := true
		installedAppVersionHistory, err := impl.installedAppVersionHistoryRepository.GetLatestInstalledAppVersionHistoryByInstalledAppId(installedApp.Id)
		if err != nil {
			impl.logger.Errorw("error in getting latest installedAppVersionHistory by installedAppId", "err", err, "installedAppId", installedApp.Id)
			return nil, isTimelineUpdated
		}
		dc, err := impl.deploymentConfigService.GetConfigForHelmApps(installedApp.AppId, installedApp.EnvironmentId)
		if err != nil {
			impl.logger.Errorw("error, GetConfigForDevtronApps", "appId", installedApp.AppId, "environmentId", installedApp.EnvironmentId, "err", err)
			return nil, isTimelineUpdated
		}
		applicationObjectClusterId := dc.GetApplicationObjectClusterId()

		impl.logger.Debugw("ARGO_PIPELINE_STATUS_UPDATE_REQ", "stage", "checkingDeploymentStatus", "installedApp", installedApp, "installedAppVersionHistory", installedAppVersionHistory)
		if util3.IsTerminalRunnerStatus(installedAppVersionHistory.Status) {
			// drop event
			return nil, isTimelineUpdated
		}
		if impl.acdConfig.IsManualSyncEnabled() {
			isArgoAppSynced := impl.pipelineStatusTimelineService.GetArgoAppSyncStatusForAppStore(installedAppVersionHistory.Id)
			if !isArgoAppSynced {
				return nil, isTimelineUpdated
			}
		}
		appDetails, err := impl.appRepository.FindActiveById(installedApp.AppId)
		if err != nil {
			impl.logger.Errorw("error in getting appDetails from appId", "err", err)
			return nil, isTimelineUpdated
		}
		// TODO if Environment object in installedApp is nil then fetch envDetails also from envRepository
		envDetail, err := impl.envRepository.FindById(installedApp.EnvironmentId)
		if err != nil {
			impl.logger.Errorw("error in getting envDetails from environment id", "err", err)
			return nil, isTimelineUpdated
		}
		// ArgoCD application nam: format: <appName>-<envName>
		acdAppName := util3.BuildDeployedAppName(appDetails.AppName, envDetail.Name)

		// this should only be called when we have git-ops configured
		// try fetching status from argo cd

		app, err := impl.argocdClientWrapperService.GetArgoAppByName(context.Background(), acdAppName)
		if err != nil {
			impl.logger.Errorw("error in getting acd application", "err", err, "installedApp", installedApp)
			// updating cdWfr status
			installedAppVersionHistory.SetStatus(cdWorkflow2.WorkflowUnableToFetchState)
			installedAppVersionHistory.UpdateAuditLog(1)
			installedAppVersionHistory, err = impl.installedAppVersionHistoryRepository.UpdateInstalledAppVersionHistory(installedAppVersionHistory, nil)
			if err != nil {
				impl.logger.Errorw("error on update installedAppVersionHistory", "installedAppVersionHistory", installedAppVersionHistory, "err", err)
				return err, isTimelineUpdated
			}
			// creating installedApp pipeline status timeline
			timeline := &pipelineConfig.PipelineStatusTimeline{
				InstalledAppVersionHistoryId: installedAppVersionHistory.Id,
				Status:                       timelineStatus.TIMELINE_STATUS_UNABLE_TO_FETCH_STATUS,
				StatusDetail:                 "Failed to connect to Argo CD to fetch deployment status.",
				StatusTime:                   time.Now(),
				AuditLog: sql.AuditLog{
					CreatedBy: userId,
					CreatedOn: time.Now(),
					UpdatedBy: userId,
					UpdatedOn: time.Now(),
				},
			}
			err = impl.pipelineStatusTimelineService.SaveTimeline(timeline, nil)
			if err != nil {
				impl.logger.Errorw("error in creating timeline status for app", "err", err, "timeline", timeline)
				return err, isTimelineUpdated
			}
		} else {
			if app == nil {
				impl.logger.Errorw("found empty argo application object", "appName", acdAppName)
				return fmt.Errorf("found empty argo application object"), isTimelineUpdated
			}
			isSucceeded, isTimelineUpdated, pipelineOverride, err = impl.appService.UpdateDeploymentStatusForGitOpsPipelines(app, applicationObjectClusterId, time.Now(), isAppStore)
			if err != nil {
				impl.logger.Errorw("error in updating deployment status for gitOps cd pipelines", "app", app)
				return err, isTimelineUpdated
			}
			appStatus := app.Status.Health.Status
			err = impl.appStatusService.UpdateStatusWithAppIdEnvId(installedApp.AppId, installedApp.EnvironmentId, string(appStatus))
			if err != nil {
				impl.logger.Errorw("error occurred while updating app-status for installed app", "err", err, "appId", installedApp.AppId, "envId", installedApp.EnvironmentId)
				impl.logger.Debugw("ignoring the error, UpdateStatusWithAppIdEnvId", "err", err, "appId", installedApp.AppId, "envId", installedApp.EnvironmentId)
			}
		}
		if isSucceeded {
			// handling deployment success event
			// updating cdWfr status
			installedAppVersionHistory.SetStatus(cdWorkflow2.WorkflowSucceeded)
			installedAppVersionHistory.SetFinishedOn()
			installedAppVersionHistory.UpdateAuditLog(1)
			installedAppVersionHistory, err = impl.installedAppVersionHistoryRepository.UpdateInstalledAppVersionHistory(installedAppVersionHistory, nil)
			if err != nil {
				impl.logger.Errorw("error on update installedAppVersionHistory", "installedAppVersionHistory", installedAppVersionHistory, "err", err)
				return err, isTimelineUpdated
			}

		}
	}

	return nil, isTimelineUpdated
}

func (impl *WorkflowStatusServiceImpl) CheckAndSendArgoPipelineStatusSyncEventIfNeeded(pipelineId int, installedAppVersionId int,
	userId int32, isAppStoreApplication bool) {
	var lastSyncTime time.Time
	var err error
	if isAppStoreApplication {
		lastSyncTime, err = impl.pipelineStatusSyncDetailService.GetLastSyncTimeForLatestInstalledAppVersionHistoryByInstalledAppVersionId(installedAppVersionId)
	} else {
		lastSyncTime, err = impl.pipelineStatusSyncDetailService.GetLastSyncTimeForLatestCdWfrByCdPipelineId(pipelineId)
	}
	if err != nil {
		impl.logger.Errorw("error in getting last sync time by pipelineId", "err", err, "pipelineId", pipelineId, "installedAppVersionHistoryId", installedAppVersionId)
		return
	}

	// sync ArgoCd application
	if pipelineId != 0 {
		// for devtron applications, all restart cases has been handled through user deployment request processing.
		// refer function: WorkflowEventProcessorImpl.ProcessIncompleteDeploymentReq()
		// hence, sync ACD app for cd pipeline will not be necessary.

		// checking if git commit timeline exists for the latest CdWorkflowRunner
		latestCdWfr, err := impl.cdWorkflowRepository.FindLatestByPipelineIdAndRunnerType(pipelineId, bean2.CD_WORKFLOW_TYPE_DEPLOY)
		if err != nil {
			impl.logger.Errorw("error in checking if terminal status timeline exists by wfrId", "err", err, "pipelineId", pipelineId)
			return
		}
		preRequiredStatusExists, err := impl.pipelineStatusTimelineRepository.CheckIfTimelineStatusPresentByWfrId(latestCdWfr.Id, timelineStatus.TIMELINE_STATUS_GIT_COMMIT)
		if err != nil {
			impl.logger.Errorw("error in checking if terminal status timeline exists by wfrId", "err", err, "wfrId", latestCdWfr.Id)
			return
		}
		if !preRequiredStatusExists {
			impl.logger.Errorw("pre-condition failed: timeline for GIT_COMMIT is missing for wfrId", "wfrId", latestCdWfr.Id)
			return
		}
	}
	if installedAppVersionId != 0 {
		err := impl.syncACDHelmApps(impl.AppConfig.ArgoCdManualSyncCronPipelineDeployedBefore, installedAppVersionId)
		if err != nil {
			impl.logger.Errorw("error in syncing Helm apps deployed via argoCD", "err", err)
			return
		}
	}

	// pipelineId can be cdPipelineId or installedAppVersionId, using isAppStoreApplication flag to identify between them
	if lastSyncTime.IsZero() || (!lastSyncTime.IsZero() && time.Since(lastSyncTime) > 5*time.Second) {
		// create new nats event
		err = impl.cdPipelineEventPublishService.PublishArgoTypePipelineSyncEvent(pipelineId, installedAppVersionId, userId, isAppStoreApplication)
		if err != nil {
			impl.logger.Errorw("error, PublishArgoTypePipelineSyncEvent", "err", err)
		}
	}
}

func (impl *WorkflowStatusServiceImpl) CheckArgoAppStatusPeriodicallyAndUpdateInDb(getPipelineDeployedBeforeMinutes int, getPipelineDeployedWithinHours int) error {
	pipelines, err := impl.pipelineRepository.GetArgoPipelinesHavingLatestTriggerStuckInNonTerminalStatuses(getPipelineDeployedBeforeMinutes, getPipelineDeployedWithinHours)
	if err != nil {
		impl.logger.Errorw("error in getting pipelines having latest trigger stuck in non terminal statuses", "err", err)
		return err
	}
	impl.logger.Debugw("received stuck argo cd pipelines", "pipelines", pipelines, "number of pipelines", len(pipelines))

	for _, pipeline := range pipelines {
		impl.CheckAndSendArgoPipelineStatusSyncEventIfNeeded(pipeline.Id, 0, 1, false)
	}

	installedAppVersions, err := impl.installedAppRepository.GetArgoPipelinesHavingLatestTriggerStuckInNonTerminalStatusesForAppStore(getPipelineDeployedBeforeMinutes, getPipelineDeployedWithinHours)
	if err != nil {
		impl.logger.Errorw("error in getting installedAppVersions having latest trigger stuck in non terminal statuses", "err", err)
		return err
	}
	impl.logger.Debugw("received stuck argo installed appStore app", "installedAppVersions", installedAppVersions, "number of triggers", len(installedAppVersions))

	for _, installedAppVersion := range installedAppVersions {
		impl.CheckAndSendArgoPipelineStatusSyncEventIfNeeded(0, installedAppVersion.Id, 1, true)
	}
	return nil
}

func (impl *WorkflowStatusServiceImpl) CheckArgoPipelineTimelineStatusPeriodicallyAndUpdateInDb(pendingSinceSeconds int, timeForDegradation int) error {
	// getting all the progressing status that are stuck since some time after kubectl apply success sync stage
	// and are not eligible for CheckArgoAppStatusPeriodicallyAndUpdateInDb
	pipelines, err := impl.pipelineRepository.GetArgoPipelinesHavingTriggersStuckInLastPossibleNonTerminalTimelines(pendingSinceSeconds, timeForDegradation)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("err in GetArgoPipelinesHavingTriggersStuckInLastPossibleNonTerminalTimelines", "err", err)
		return err
	}
	impl.logger.Debugw("received argo cd pipelines stuck at kubectl apply synced stage", "pipelines", pipelines)

	installedAppVersions, err := impl.installedAppRepository.GetArgoPipelinesHavingTriggersStuckInLastPossibleNonTerminalTimelinesForAppStore(pendingSinceSeconds, timeForDegradation)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("err in GetArgoPipelinesHavingTriggersStuckInLastPossibleNonTerminalTimelinesForAppStore", "err", err)
		return err
	}

	impl.logger.Debugw("received argo appStore application stuck at kubectl apply synced stage", "pipelines", installedAppVersions)
	for _, pipeline := range pipelines {
		impl.CheckAndSendArgoPipelineStatusSyncEventIfNeeded(pipeline.Id, 0, 1, false)
	}

	for _, installedAppVersion := range installedAppVersions {
		impl.CheckAndSendArgoPipelineStatusSyncEventIfNeeded(0, installedAppVersion.Id, 1, true)
	}
	return nil
}

func (impl *WorkflowStatusServiceImpl) syncACDHelmApps(deployedBeforeMinutes int, installedAppVersionId int) error {
	if impl.acdConfig.IsAutoSyncEnabled() {
		// don't check for apps if auto sync is enabled
		return nil
	}
	installedAppVersionHistory, err := impl.installedAppVersionHistoryRepository.GetLatestInstalledAppVersionHistory(installedAppVersionId)
	if err != nil {
		impl.logger.Errorw("error in getting latest cdWfr by cdPipelineId", "err", err, "installedAppVersionId", installedAppVersionId)
		return err
	}
	if util3.IsTerminalRunnerStatus(installedAppVersionHistory.Status) {
		return nil
	}
	installedAppVersionHistoryId := installedAppVersionHistory.Id
	pipelineStatusTimeline, err := impl.pipelineStatusTimelineRepository.FetchLatestTimelinesByInstalledAppVersionHistoryId(installedAppVersionHistoryId)
	if err != nil {
		impl.logger.Errorw("error in fetching latest pipeline status by cdWfrId", "err", err)
		return err
	}
	if pipelineStatusTimeline.Status == timelineStatus.TIMELINE_STATUS_ARGOCD_SYNC_INITIATED && time.Since(pipelineStatusTimeline.StatusTime) >= time.Minute*time.Duration(deployedBeforeMinutes) {
		installedApp, err := impl.installedAppReadService.GetInstalledAppByInstalledAppVersionId(installedAppVersionHistory.InstalledAppVersionId)
		if err != nil {
			impl.logger.Errorw("error in fetching installed_app by installedAppVersionId", "err", err)
			return err
		}
		appDetails, err := impl.appRepository.FindActiveById(installedApp.AppId)
		if err != nil {
			impl.logger.Errorw("error in getting appDetails from appId", "err", err)
			return err
		}
		envDetails, err := impl.envRepository.FindById(installedApp.EnvironmentId)
		if err != nil {
			impl.logger.Errorw("error in fetching environment by envId", "err", err)
		}
		argoAppName := util3.BuildDeployedAppName(appDetails.AppName, envDetails.Name)
		ctx := context.Background()
		syncTime := time.Now()
		deploymentConfig, err := impl.deploymentConfigService.GetConfigForHelmApps(appDetails.Id, envDetails.Id)
		if err != nil {
			impl.logger.Errorw("error in getting deployment config db object by appId and envId", "appId", appDetails.Id, "envId", envDetails.Id, "err", err)
			return err
		}
		if deploymentConfig.IsArgoAppSyncAndRefreshSupported() {
			return nil
		}
		targetRevision := deploymentConfig.GetTargetRevision()
		syncErr := impl.argocdClientWrapperService.SyncArgoCDApplicationIfNeededAndRefresh(ctx, argoAppName, targetRevision)
		if syncErr != nil {
			impl.logger.Errorw("error in syncing argoCD app", "err", syncErr)
			timelineObject := impl.pipelineStatusTimelineService.NewHelmAppDeploymentStatusTimelineDbObject(installedAppVersionHistoryId, timelineStatus.TIMELINE_STATUS_DEPLOYMENT_FAILED, fmt.Sprintf("error occured in syncing argocd application. err: %s", syncErr.Error()), 1)
			_ = impl.pipelineStatusTimelineService.SaveTimeline(timelineObject, nil)
			installedAppVersionHistory.MarkDeploymentFailed(syncErr)
			installedAppVersionHistory.UpdateAuditLog(1)
			_, installedAppUpdateErr := impl.installedAppVersionHistoryRepository.UpdateInstalledAppVersionHistory(installedAppVersionHistory, nil)
			if installedAppUpdateErr != nil {
				impl.logger.Errorw("error in updating cd workflow runner as failed in argocd app sync cron", "err", err)
				return err
			}
			return nil
		}
		timeline := &pipelineConfig.PipelineStatusTimeline{
			InstalledAppVersionHistoryId: installedAppVersionHistoryId,
			StatusTime:                   syncTime,
			Status:                       timelineStatus.TIMELINE_STATUS_ARGOCD_SYNC_COMPLETED,
			StatusDetail:                 timelineStatus.TIMELINE_DESCRIPTION_ARGOCD_SYNC_COMPLETED,
		}
		timeline.CreateAuditLog(1)
		_, err = impl.pipelineStatusTimelineService.SaveTimelineIfNotAlreadyPresent(timeline, nil)
	}
	return nil
}

func (impl *WorkflowStatusServiceImpl) CheckFluxAppStatusPeriodicallyAndUpdateInDb(fluxPipelineStatusCheckEligibleTime int, getPipelineDeployedWithinHours int, cdPipelineTimeoutDuration int) error {
	wfrList, err := impl.cdWorkflowRepository.GetLatestTriggersOfPipelinesStuckInNonTerminalStatuses(getPipelineDeployedWithinHours, util2.PIPELINE_DEPLOYMENT_TYPE_FLUX)
	if err != nil {
		impl.logger.Errorw("error in getting latest triggers of helm pipelines which are stuck in non terminal statuses", "err", err)
		return err
	}
	impl.logger.Debugw("checking helm app status for non terminal deployment triggers", "wfrList", wfrList, "number of wfr", len(wfrList))
	for _, wfr := range wfrList {
		if time.Now().Sub(wfr.StartedOn) <= time.Duration(fluxPipelineStatusCheckEligibleTime)*time.Second {
			// if wfr is updated within configured time then do not include for this cron cycle
			continue
		}

		appIdentifier := &bean4.FluxAppIdentifier{
			ClusterId:      wfr.CdWorkflow.Pipeline.Environment.ClusterId,
			Namespace:      wfr.CdWorkflow.Pipeline.Environment.Namespace,
			Name:           wfr.CdWorkflow.Pipeline.DeploymentAppName,
			IsKustomizeApp: false,
		}
		pipeline := wfr.CdWorkflow.Pipeline

		// getting latest pipelineOverride for app (by appId and envId)
		pipelineOverride, err := impl.pipelineOverrideRepository.FindLatestByAppIdAndEnvId(pipeline.AppId, pipeline.EnvironmentId, bean3.FluxCd)
		if err != nil {
			impl.logger.Errorw("error in getting latest pipelineOverride by appId and envId", "err", err, "appId", pipeline.AppId, "envId", pipeline.EnvironmentId)
			return err
		}

		if isWfrUpdated := impl.workflowDagExecutor.UpdateWorkflowRunnerStatusForFluxDeployment(appIdentifier, wfr, pipelineOverride); !isWfrUpdated {
			continue
		}

		wfr.UpdateAuditLog(1)
		err = impl.cdWorkflowRunnerService.UpdateCdWorkflowRunnerWithStage(wfr)
		if err != nil {
			impl.logger.Errorw("error on update cd workflow runner", "wfr", wfr, "err", err)
			return err
		}

		if wfr.Status == cdWorkflow2.WorkflowFailed {
			err = impl.pipelineStatusTimelineService.MarkPipelineStatusTimelineFailed(wfr.RefCdWorkflowRunnerId, "Deployment failed")
			if err != nil {
				impl.logger.Errorw("error updating CdPipelineStatusTimeline", "err", err)
				return err
			}
			impl.deploymentEventHandler.WriteCDNotificationEventAsync(pipelineOverride.Pipeline.AppId, pipelineOverride.Pipeline.EnvironmentId, pipelineOverride, util.Fail)
		}

		appId := wfr.CdWorkflow.Pipeline.AppId
		envId := wfr.CdWorkflow.Pipeline.EnvironmentId
		envDeploymentConfig, err := impl.deploymentConfigService.GetConfigForDevtronApps(appId, envId)
		if err != nil {
			impl.logger.Errorw("error in fetching environment deployment config by appId and envId", "appId", appId, "envId", envId, "err", err)
			return err
		}
		if slices.Contains(cdWorkflow2.WfrTerminalStatusList, wfr.Status) {
			util3.TriggerCDMetrics(cdWorkflow.GetTriggerMetricsFromRunnerObj(wfr, envDeploymentConfig), impl.config.ExposeCDMetrics)
		}

		impl.logger.Infow("updated workflow runner status for helm app", "wfr", wfr)
		if wfr.Status == cdWorkflow2.WorkflowSucceeded {
			timeline := impl.pipelineStatusTimelineService.NewDevtronAppPipelineStatusTimelineDbObject(wfr.Id, timelineStatus.TIMELINE_STATUS_APP_HEALTHY, "App status is Healthy.", 1)
			_, err = impl.pipelineStatusTimelineService.SaveTimelineIfNotAlreadyPresent(timeline, nil)
			if err != nil {
				impl.logger.Errorw("error in saving timeline status for helm app", "wfr.Id", wfr.Id, "err", err)
				return err
			}
			impl.deploymentEventHandler.WriteCDNotificationEventAsync(pipelineOverride.Pipeline.AppId, pipelineOverride.Pipeline.EnvironmentId, pipelineOverride, util.Success)
			err = impl.workflowDagExecutor.HandleDeploymentSuccessEvent(bean3.TriggerContext{}, pipelineOverride)
			if err != nil {
				impl.logger.Errorw("error on handling deployment success event", "wfr", wfr, "err", err)
				return err
			}
		}
	}
	return nil
}
