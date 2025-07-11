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

package validation

import (
	"context"
	errors3 "errors"
	"fmt"
	apiBean "github.com/devtron-labs/devtron/api/bean/gitOps"
	"github.com/devtron-labs/devtron/internal/constants"
	"github.com/devtron-labs/devtron/internal/util"
	"github.com/devtron-labs/devtron/pkg/appStore/installedApp/service/FullMode"
	chartService "github.com/devtron-labs/devtron/pkg/chart"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/config"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/config/bean"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/git"
	bean2 "github.com/devtron-labs/devtron/pkg/deployment/gitOps/git/bean"
	gitOpsBean "github.com/devtron-labs/devtron/pkg/deployment/gitOps/validation/bean"
	globalUtil "github.com/devtron-labs/devtron/util"
	"github.com/microsoft/azure-devops-go-api/azuredevops"
	"github.com/xanzy/go-gitlab"
	"go.uber.org/zap"
	"net/http"
	"os"
	"strings"
	"time"
)

type GitOpsValidationService interface {
	// GitOpsValidateDryRun performs the following validations:
	// "Get Repo URL", "Create Repo (if it doesn't exist)", "Create Readme", "Clone Http", "Clone Ssh", "Commit On Rest", "Push", "Delete Repo"
	// And returns: gitOps.DetailedErrorGitOpsConfigResponse
	GitOpsValidateDryRun(isArgoModuleInstalled bool, config *apiBean.GitOpsConfigDto) apiBean.DetailedErrorGitOpsConfigResponse
	// ValidateGitOpsRepoUrl performs the following validations:
	// "Organisational URL Validation", "Unique GitOps Repo"
	// And returns: SanitisedRepoUrl and error
	ValidateGitOpsRepoUrl(request *gitOpsBean.ValidateGitOpsRepoUrlRequest) (string, error)
	// ValidateCustomGitOpsConfig performs the following validations:
	// "Get Repo URL", "Create Repo (if it doesn't exist)", "Organisational URL Validation", "Unique GitOps Repo"
	// And returns: RepoUrl and isNew Repository url and error
	ValidateCustomGitOpsConfig(request gitOpsBean.ValidateGitOpsRepoRequest) (string, bool, error)
}

type GitOpsValidationServiceImpl struct {
	logger                  *zap.SugaredLogger
	gitFactory              *git.GitFactory
	gitOpsConfigReadService config.GitOpsConfigReadService
	gitOperationService     git.GitOperationService
	chartTemplateService    util.ChartTemplateService
	chartService            chartService.ChartService
	installedAppService     FullMode.InstalledAppDBExtendedService
}

func NewGitOpsValidationServiceImpl(Logger *zap.SugaredLogger,
	gitFactory *git.GitFactory,
	gitOperationService git.GitOperationService,
	gitOpsConfigReadService config.GitOpsConfigReadService,
	chartTemplateService util.ChartTemplateService,
	chartService chartService.ChartService,
	installedAppService FullMode.InstalledAppDBExtendedService) *GitOpsValidationServiceImpl {
	return &GitOpsValidationServiceImpl{
		logger:                  Logger,
		gitFactory:              gitFactory,
		gitOpsConfigReadService: gitOpsConfigReadService,
		gitOperationService:     gitOperationService,
		chartTemplateService:    chartTemplateService,
		chartService:            chartService,
		installedAppService:     installedAppService,
	}
}

func (impl *GitOpsValidationServiceImpl) GitOpsValidateDryRun(isArgoModuleInstalled bool, config *apiBean.GitOpsConfigDto) apiBean.DetailedErrorGitOpsConfigResponse {
	if config.AllowCustomRepository || !isArgoModuleInstalled {
		return apiBean.DetailedErrorGitOpsConfigResponse{
			ValidationSkipped: true,
		}
	}
	detailedErrorGitOpsConfigActions := git.DetailedErrorGitOpsConfigActions{}
	detailedErrorGitOpsConfigActions.StageErrorMap = make(map[string]error)

	if strings.ToUpper(config.Provider) == bean.BITBUCKET_PROVIDER {
		config.Host = git.BITBUCKET_CLONE_BASE_URL
		config.BitBucketProjectKey = strings.ToUpper(config.BitBucketProjectKey)
	}
	client, gitService, err := impl.gitFactory.NewClientForValidation(config)
	if err != nil {
		impl.logger.Errorw("error in creating new client for validation")
		detailedErrorGitOpsConfigActions.StageErrorMap[fmt.Sprintf("error in connecting with %s", strings.ToUpper(config.Provider))] = impl.extractErrorMessageByProvider(err, config.Provider)
		detailedErrorGitOpsConfigActions.ValidatedOn = time.Now()
		detailedErrorGitOpsConfigResponse := impl.convertDetailedErrorToResponse(detailedErrorGitOpsConfigActions)
		return detailedErrorGitOpsConfigResponse
	}
	appName := gitOpsBean.DryrunRepoName + globalUtil.Generate(6)
	//getting user name & emailId for commit author data
	userEmailId, userName := impl.gitOpsConfigReadService.GetUserEmailIdAndNameForGitOpsCommit(config.UserId)
	config.UserEmailId = userEmailId
	config.GitRepoName = appName
	config.TargetRevision = globalUtil.GetDefaultTargetRevision()
	ctx := context.Background()
	repoUrl, _, _, detailedErrorCreateRepo := client.CreateRepository(ctx, config)

	detailedErrorGitOpsConfigActions.StageErrorMap = detailedErrorCreateRepo.StageErrorMap
	detailedErrorGitOpsConfigActions.SuccessfulStages = detailedErrorCreateRepo.SuccessfulStages

	for stage, stageErr := range detailedErrorGitOpsConfigActions.StageErrorMap {
		if stage == gitOpsBean.CreateRepoStage || stage == gitOpsBean.GetRepoUrlStage {
			_, ok := detailedErrorGitOpsConfigActions.StageErrorMap[gitOpsBean.GetRepoUrlStage]
			if ok {
				detailedErrorGitOpsConfigActions.StageErrorMap[fmt.Sprintf("error in connecting with %s", strings.ToUpper(config.Provider))] = impl.extractErrorMessageByProvider(stageErr, config.Provider)
				delete(detailedErrorGitOpsConfigActions.StageErrorMap, gitOpsBean.GetRepoUrlStage)
			} else {
				detailedErrorGitOpsConfigActions.StageErrorMap[gitOpsBean.CreateRepoStage] = impl.extractErrorMessageByProvider(stageErr, config.Provider)
			}
			detailedErrorGitOpsConfigActions.ValidatedOn = time.Now()
			detailedErrorGitOpsConfigResponse := impl.convertDetailedErrorToResponse(detailedErrorGitOpsConfigActions)
			return detailedErrorGitOpsConfigResponse
		} else if stage == gitOpsBean.CloneHttp || stage == gitOpsBean.CreateReadmeStage {
			detailedErrorGitOpsConfigActions.StageErrorMap[stage] = impl.extractErrorMessageByProvider(stageErr, config.Provider)
		}
	}
	chartDir := fmt.Sprintf("%s-%s", appName, impl.chartTemplateService.GetDir())
	clonedDir := gitService.GetCloneDirectory(chartDir)
	if _, err := os.Stat(clonedDir); os.IsNotExist(err) {
		clonedDir, err = gitService.Clone(repoUrl, chartDir, config.TargetRevision)
		if err != nil {
			impl.logger.Errorw("error in cloning repo", "url", repoUrl, "err", err)
			detailedErrorGitOpsConfigActions.StageErrorMap[gitOpsBean.CloneStage] = err
		} else {
			detailedErrorGitOpsConfigActions.SuccessfulStages = append(detailedErrorGitOpsConfigActions.SuccessfulStages, gitOpsBean.CloneStage)
		}
	}

	commit, err := gitService.CommitAndPushAllChanges(ctx, clonedDir, config.TargetRevision, "first commit", userName, userEmailId)
	if err != nil {
		impl.logger.Errorw("error in commit and pushing git", "err", err)
		if commit == "" {
			detailedErrorGitOpsConfigActions.StageErrorMap[gitOpsBean.CommitOnRestStage] = err
		} else {
			detailedErrorGitOpsConfigActions.StageErrorMap[gitOpsBean.PushStage] = err
		}
	} else {
		detailedErrorGitOpsConfigActions.SuccessfulStages = append(detailedErrorGitOpsConfigActions.SuccessfulStages, gitOpsBean.CommitOnRestStage, gitOpsBean.PushStage)
	}

	err = client.DeleteRepository(config)
	if err != nil {
		impl.logger.Errorw("error in deleting repo", "err", err)
		//here below the assignment of delete is removed for making this stage optional, and it's failure not preventing it from saving/updating gitOps config
		//detailedErrorGitOpsConfigActions.StageErrorMap[DeleteRepoStage] = impl.extractErrorMessageByProvider(err, config.Provider)
		detailedErrorGitOpsConfigActions.DeleteRepoFailed = true
	} else {
		detailedErrorGitOpsConfigActions.SuccessfulStages = append(detailedErrorGitOpsConfigActions.SuccessfulStages, gitOpsBean.DeleteRepoStage)
	}
	detailedErrorGitOpsConfigActions.ValidatedOn = time.Now()
	defer impl.chartTemplateService.CleanDir(clonedDir)
	detailedErrorGitOpsConfigResponse := impl.convertDetailedErrorToResponse(detailedErrorGitOpsConfigActions)
	return detailedErrorGitOpsConfigResponse
}

func (impl *GitOpsValidationServiceImpl) ValidateGitOpsRepoUrl(request *gitOpsBean.ValidateGitOpsRepoUrlRequest) (string, error) {
	// Validate: Organisational URL starts
	sanitiseGitRepoUrl, err := impl.validateForGitOpsOrg(request)
	if err != nil {
		impl.logger.Errorw("non-organisational custom gitops repo validation error", "err", err)
		return sanitiseGitRepoUrl, err
	}
	// Validate: Organisational URL ends

	// Validate: Unique GitOps repository URL starts
	isValid := impl.validateUniqueGitOpsRepo(sanitiseGitRepoUrl, request.AppId)
	if !isValid {
		impl.logger.Errorw("git repo url already exists", "repo url", request.RequestedGitUrl)
		errMsg := fmt.Sprintf("invalid git repository! '%s' is already in use by another application! Use a different repository", request.RequestedGitUrl)
		return sanitiseGitRepoUrl, util.NewApiError(http.StatusBadRequest, errMsg, errMsg).
			WithCode(constants.GitOpsURLAlreadyInUse)
	}
	// Validate: Unique GitOps repository URL ends
	return sanitiseGitRepoUrl, nil
}

func (impl *GitOpsValidationServiceImpl) ValidateCustomGitOpsConfig(request gitOpsBean.ValidateGitOpsRepoRequest) (string, bool, error) {
	gitOpsRepoName := ""
	if request.GitRepoURL == apiBean.GIT_REPO_DEFAULT || len(request.GitRepoURL) == 0 {
		gitOpsRepoName = impl.gitOpsConfigReadService.GetGitOpsRepoName(request.AppName)
	} else {
		gitOpsRepoName = impl.gitOpsConfigReadService.GetGitOpsRepoNameFromUrl(request.GitRepoURL)
	}
	if len(request.TargetRevision) == 0 {
		request.TargetRevision = globalUtil.GetDefaultTargetRevision()
	}
	// CreateGitRepositoryForDevtronApp will try to create repository if not present, and returns a sanitized repo url, use this repo url to maintain uniformity
	chartGitAttribute, err := impl.gitOperationService.CreateGitRepositoryForDevtronApp(context.Background(), gitOpsRepoName, request.TargetRevision, request.UserId)
	if err != nil {
		impl.logger.Errorw("error in validating custom gitops repo", "err", err)
		return "", false, impl.extractErrorMessageByProvider(err, request.GitOpsProvider)
	}

	if request.GitRepoURL != apiBean.GIT_REPO_DEFAULT && len(request.GitRepoURL) != 0 {
		// For custom git repo; we expect the chart is not present hence setting isNew flag to be true.
		chartGitAttribute.IsNewRepo = true
		validateGitRepoRequest := &gitOpsBean.ValidateGitOpsRepoUrlRequest{
			RequestedGitUrl: request.GitRepoURL,
			DesiredGitUrl:   chartGitAttribute.RepoUrl,
			UseActiveGitOps: true,
		}
		_, validationErr := impl.ValidateGitOpsRepoUrl(validateGitRepoRequest)
		if validationErr != nil {
			impl.logger.Errorw("error in validating gitops repo url", "err", validationErr)
			return "", false, validationErr
		}
	}
	return chartGitAttribute.RepoUrl, chartGitAttribute.IsNewRepo, nil
}

func (impl *GitOpsValidationServiceImpl) getDesiredGitRepoUrl(request *gitOpsBean.ValidateGitOpsRepoUrlRequest, gitOpsConfig *apiBean.GitOpsConfigDto) (string, error) {
	if len(request.DesiredGitUrl) != 0 {
		return request.DesiredGitUrl, nil
	}
	client, _, clientErr := impl.gitFactory.NewClientForValidation(gitOpsConfig)
	if clientErr != nil {
		impl.logger.Errorw("error in creating new client for validation", "clientErr", clientErr, "request", request)
		return "", clientErr
	}
	gitOpsConfig.GitRepoName = impl.gitOpsConfigReadService.GetGitOpsRepoNameFromUrl(request.RequestedGitUrl)
	desiredRepoUrl, _, err := client.GetRepoUrl(gitOpsConfig)
	if err != nil {
		impl.logger.Errorw("error in getting repo url", "err", err, "request", request)
		return "", err
	}
	if len(desiredRepoUrl) == 0 {
		return "", errors3.New(fmt.Sprintf("repo not found in saved provider"))
	}
	return desiredRepoUrl, nil
}

func (impl *GitOpsValidationServiceImpl) getMatchedGitopsConfig(request *gitOpsBean.ValidateGitOpsRepoUrlRequest) (*apiBean.GitOpsConfigDto, error) {
	if request.UseActiveGitOps {
		matchedGitopsConfig, err := impl.gitOpsConfigReadService.GetGitOpsConfigActive()
		if err != nil {
			impl.logger.Errorw("error in fetching active gitOps provider", "err", err)
			return nil, err
		}
		return matchedGitopsConfig, err
	}
	matchedGitopsConfig, err := impl.gitOpsConfigReadService.GetGitOpsProviderByRepoURL(request.RequestedGitUrl)
	if err != nil {
		impl.logger.Errorw("error in fetching gitOps provider by repo url", "err", err)
		return nil, err
	}
	return matchedGitopsConfig, err
}

func (impl *GitOpsValidationServiceImpl) validateForGitOpsOrg(request *gitOpsBean.ValidateGitOpsRepoUrlRequest) (string, error) {
	matchedGitopsConfig, err := impl.getMatchedGitopsConfig(request)
	if err != nil {
		impl.logger.Errorw("error in getting matched gitops config", "err", err, "request", request)
		errMsg := fmt.Sprintf("error in getting matched gitops config: %s", err.Error())
		return "", util.NewApiError(http.StatusBadRequest, errMsg, errMsg).
			WithCode(constants.GitOpsNotConfigured)
	}
	desiredRepoUrl, gitErr := impl.getDesiredGitRepoUrl(request, matchedGitopsConfig)
	if gitErr != nil {
		impl.logger.Errorw("error in getting desired git repo url", "err", gitErr, "request", request)
		errMsg := fmt.Sprintf("error in getting desired git repo url: %s", gitErr.Error())
		return "", util.NewApiError(http.StatusBadRequest, errMsg, errMsg).
			WithCode(constants.GitOpsNotConfigured)
	}
	sanitiseGitRepoUrl := git.SanitiseCustomGitRepoURL(matchedGitopsConfig, request.RequestedGitUrl)
	orgRepoUrl := strings.TrimSuffix(desiredRepoUrl, ".git")
	if !strings.Contains(strings.ToLower(sanitiseGitRepoUrl), strings.ToLower(orgRepoUrl)) {
		// If the repo is non-organizational, then return error
		impl.logger.Debugw("non-organisational custom gitops repo", "expected repo", desiredRepoUrl, "user given repo", sanitiseGitRepoUrl, "request", request)
		return "", impl.getValidationErrorForNonOrganisationalURL(matchedGitopsConfig)
	}
	return desiredRepoUrl, nil
}

func (impl *GitOpsValidationServiceImpl) extractErrorMessageByProvider(err error, provider string) error {
	switch provider {
	case bean2.GITLAB_PROVIDER:
		errorResponse, ok := err.(*gitlab.ErrorResponse)
		if ok {
			errorMessage := fmt.Errorf("gitlab client error: %s", errorResponse.Message)
			return errorMessage
		}
		return fmt.Errorf("gitlab client error: %s", err.Error())
	case bean2.AZURE_DEVOPS_PROVIDER:
		if errorResponse, ok := err.(azuredevops.WrappedError); ok {
			errorMessage := fmt.Errorf("azure devops client error: %s", *errorResponse.Message)
			return errorMessage
		} else if errorResponse, ok := err.(*azuredevops.WrappedError); ok {
			errorMessage := fmt.Errorf("azure devops client error: %s", *errorResponse.Message)
			return errorMessage
		}
		return fmt.Errorf("azure devops client error: %s", err.Error())
	case bean2.BITBUCKET_PROVIDER:
		return fmt.Errorf("bitbucket client error: %s", err.Error())
	case bean2.GITHUB_PROVIDER:
		return fmt.Errorf("github client error: %s", err.Error())
	}
	return err
}

func (impl *GitOpsValidationServiceImpl) convertDetailedErrorToResponse(detailedErrorGitOpsConfigActions git.DetailedErrorGitOpsConfigActions) (detailedErrorResponse apiBean.DetailedErrorGitOpsConfigResponse) {
	detailedErrorResponse.StageErrorMap = make(map[string]string)
	detailedErrorResponse.SuccessfulStages = detailedErrorGitOpsConfigActions.SuccessfulStages
	for stage, err := range detailedErrorGitOpsConfigActions.StageErrorMap {
		detailedErrorResponse.StageErrorMap[stage] = err.Error()
	}
	detailedErrorResponse.DeleteRepoFailed = detailedErrorGitOpsConfigActions.DeleteRepoFailed
	detailedErrorResponse.ValidatedOn = detailedErrorGitOpsConfigActions.ValidatedOn
	return detailedErrorResponse
}

func (impl *GitOpsValidationServiceImpl) getValidationErrorForNonOrganisationalURL(activeGitOpsConfig *apiBean.GitOpsConfigDto) error {
	var errorMessageKey, errorMessage string
	switch strings.ToUpper(activeGitOpsConfig.Provider) {
	case bean2.GITHUB_PROVIDER:
		errorMessageKey = "The repository must belong to GitHub organization"
		errorMessage = fmt.Sprintf("%s as configured in global configurations > GitOps", activeGitOpsConfig.GitHubOrgId)

	case bean2.GITLAB_PROVIDER:
		errorMessageKey = "The repository must belong to gitLab Group ID"
		errorMessage = fmt.Sprintf("%s as configured in global configurations > GitOps", activeGitOpsConfig.GitHubOrgId)

	case bean2.BITBUCKET_PROVIDER:
		errorMessageKey = "The repository must belong to BitBucket Workspace"
		errorMessage = fmt.Sprintf("%s as configured in global configurations > GitOps", activeGitOpsConfig.BitBucketWorkspaceId)

	case bean2.AZURE_DEVOPS_PROVIDER:
		errorMessageKey = "The repository must belong to Azure DevOps Project"
		errorMessage = fmt.Sprintf("%s as configured in global configurations > GitOps", activeGitOpsConfig.AzureProjectName)
	}
	apiErrorMsg := fmt.Sprintf("%s: %s", errorMessageKey, errorMessage)
	return util.NewApiError(http.StatusBadRequest, apiErrorMsg, apiErrorMsg).
		WithCode(constants.GitOpsOrganisationMismatch)
}

func (impl *GitOpsValidationServiceImpl) validateUniqueGitOpsRepo(repoUrl string, appId int) (isValid bool) {
	isDevtronAppRegistered, err := impl.chartService.IsGitOpsRepoAlreadyRegistered(repoUrl, appId)
	if err != nil || isDevtronAppRegistered {
		return isValid
	}
	isHelmAppRegistered, err := impl.installedAppService.IsGitOpsRepoAlreadyRegistered(repoUrl, appId)
	if err != nil || isHelmAppRegistered {
		return isValid
	}
	isValid = true
	return isValid
}
