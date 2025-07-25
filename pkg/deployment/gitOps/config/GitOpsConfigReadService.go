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

package config

import (
	"errors"
	"fmt"
	bean3 "github.com/devtron-labs/devtron/api/bean"
	bean2 "github.com/devtron-labs/devtron/api/bean/gitOps"
	"github.com/devtron-labs/devtron/internal/constants"
	"github.com/devtron-labs/devtron/internal/sql/repository"
	internalUtil "github.com/devtron-labs/devtron/internal/util"
	"github.com/devtron-labs/devtron/pkg/auth/user"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/adapter"
	"github.com/devtron-labs/devtron/pkg/deployment/gitOps/config/bean"
	gitAdapter "github.com/devtron-labs/devtron/pkg/deployment/gitOps/git/adapter"
	gitBean "github.com/devtron-labs/devtron/pkg/deployment/gitOps/git/bean"
	moduleBean "github.com/devtron-labs/devtron/pkg/module/bean"
	moduleRead "github.com/devtron-labs/devtron/pkg/module/read"
	moduleErr "github.com/devtron-labs/devtron/pkg/module/read/error"
	"github.com/devtron-labs/devtron/util"
	"github.com/devtron-labs/devtron/util/gitUtil"
	"github.com/go-pg/pg"
	"go.uber.org/zap"
	"net/http"
	"regexp"
	"strings"
)

type GitOpsConfigReadService interface {
	IsGitOpsConfigured() (*bean.GitOpsConfigurationStatus, error)
	GetUserEmailIdAndNameForGitOpsCommit(userId int32) (string, string)
	GetGitOpsRepoName(appName string) string
	GetGitOpsRepoNameFromUrl(gitRepoUrl string) string
	GetBitbucketMetadata() (*bean.BitbucketProviderMetadata, error)
	GetGitOpsConfigActive() (*bean2.GitOpsConfigDto, error)
	GetAllGitOpsConfig() ([]*bean2.GitOpsConfigDto, error)
	GetConfiguredGitOpsCount() (int, error)
	GetGitOpsProviderByRepoURL(gitRepoUrl string) (*bean2.GitOpsConfigDto, error)
	GetGitOpsById(id int) (*bean2.GitOpsConfigDto, error)
	GetGitConfig() (*gitBean.GitConfig, error)
}

type GitOpsConfigReadServiceImpl struct {
	logger             *zap.SugaredLogger
	gitOpsRepository   repository.GitOpsConfigRepository
	userService        user.UserService
	globalEnvVariables *util.GlobalEnvVariables
	moduleReadService  moduleRead.ModuleReadService
}

func NewGitOpsConfigReadServiceImpl(logger *zap.SugaredLogger,
	gitOpsRepository repository.GitOpsConfigRepository,
	userService user.UserService,
	envVariables *util.EnvironmentVariables,
	moduleReadService moduleRead.ModuleReadService) *GitOpsConfigReadServiceImpl {
	return &GitOpsConfigReadServiceImpl{
		logger:             logger,
		gitOpsRepository:   gitOpsRepository,
		userService:        userService,
		globalEnvVariables: envVariables.GlobalEnvVariables,
		moduleReadService:  moduleReadService,
	}
}

func (impl *GitOpsConfigReadServiceImpl) IsGitOpsConfigured() (*bean.GitOpsConfigurationStatus, error) {
	gitOpsConfigurationStatus := &bean.GitOpsConfigurationStatus{}
	argoModule, err := impl.moduleReadService.GetModuleInfoByName(moduleBean.ModuleNameArgoCd)
	if err != nil && !errors.Is(err, moduleErr.ModuleNotFoundError) {
		impl.logger.Errorw("error in getting argo module", "error", err)
		return gitOpsConfigurationStatus, err
	}
	gitOpsConfigurationStatus.IsArgoCdInstalled = argoModule.IsInstalled()
	gitOpsConfig, err := impl.gitOpsRepository.GetGitOpsConfigActive()
	if err != nil && !errors.Is(err, pg.ErrNoRows) {
		impl.logger.Errorw("GetGitOpsConfigActive, error while getting", "err", err)
		return gitOpsConfigurationStatus, err
	}
	if gitOpsConfig != nil && gitOpsConfig.Id > 0 {
		gitOpsConfigurationStatus.IsGitOpsConfigured = true
		gitOpsConfigurationStatus.AllowCustomRepository = gitOpsConfig.AllowCustomRepository
		gitOpsConfigurationStatus.Provider = gitOpsConfig.Provider
	}
	return gitOpsConfigurationStatus, nil
}

func (impl *GitOpsConfigReadServiceImpl) GetUserEmailIdAndNameForGitOpsCommit(userId int32) (string, string) {
	emailId := bean.GitOpsCommitDefaultEmailId
	name := bean.GitOpsCommitDefaultName
	//getting emailId associated with user
	userEmail, err := impl.userService.GetActiveEmailById(userId)
	if err != nil {
		impl.logger.Errorw("error in getting user info by id", "err", err, "id", userId)
	}
	//TODO: export constant in user bean
	if userEmail != "admin" && userEmail != "system" && len(userEmail) > 0 {
		emailId = userEmail
	} else {
		emailIdGitOps, err := impl.gitOpsRepository.GetEmailIdFromActiveGitOpsConfig()
		if err != nil {
			impl.logger.Errorw("error in getting emailId from active gitOps config", "err", err)
		} else if len(emailIdGitOps) > 0 {
			emailId = emailIdGitOps
		}
	}
	//we are getting name from emailId(replacing special characters in <user-name part of email> with space)
	emailComponents := strings.Split(emailId, "@")
	regex, _ := regexp.Compile(`[^\w]`)
	if regex != nil {
		name = regex.ReplaceAllString(emailComponents[0], " ")
	}
	return emailId, name
}

func (impl *GitOpsConfigReadServiceImpl) GetGitOpsRepoName(appName string) string {
	var repoName string
	if len(impl.globalEnvVariables.GitOpsRepoPrefix) == 0 {
		repoName = appName
	} else {
		repoName = fmt.Sprintf("%s-%s", impl.globalEnvVariables.GitOpsRepoPrefix, appName)
	}
	return repoName
}

func (impl *GitOpsConfigReadServiceImpl) GetGitOpsRepoNameFromUrl(gitRepoUrl string) string {
	return gitUtil.GetGitRepoNameFromGitRepoUrl(gitRepoUrl)
}

func (impl *GitOpsConfigReadServiceImpl) GetBitbucketMetadata() (*bean.BitbucketProviderMetadata, error) {
	metadata := &bean.BitbucketProviderMetadata{}
	gitOpsConfigBitbucket, err := impl.gitOpsRepository.GetGitOpsConfigByProvider(bean.BITBUCKET_PROVIDER)
	if err != nil && err != pg.ErrNoRows {
		impl.logger.Errorw("error in fetching gitOps bitbucket config", "err", err)
		return nil, err
	}
	if gitOpsConfigBitbucket != nil {
		metadata.BitBucketWorkspaceId = gitOpsConfigBitbucket.BitBucketWorkspaceId
		metadata.BitBucketProjectKey = gitOpsConfigBitbucket.BitBucketProjectKey
	}
	return metadata, nil
}

func (impl *GitOpsConfigReadServiceImpl) GetGitOpsConfigActive() (*bean2.GitOpsConfigDto, error) {
	model, err := impl.gitOpsRepository.GetGitOpsConfigActive()
	if err != nil {
		impl.logger.Errorw("error, GetGitOpsConfigActive", "err", err)
		return nil, err
	}
	return adapter.GetGitOpsConfigBean(model), err
}

func (impl *GitOpsConfigReadServiceImpl) GetAllGitOpsConfig() ([]*bean2.GitOpsConfigDto, error) {
	models, err := impl.gitOpsRepository.GetAllGitOpsConfig()
	if err != nil {
		impl.logger.Errorw("error, GetGitOpsConfigActive", "err", err)
		return nil, err
	}
	configs := make([]*bean2.GitOpsConfigDto, 0, len(models))
	for _, model := range models {
		configs = append(configs, &bean2.GitOpsConfigDto{
			Id:                    model.Id,
			Provider:              model.Provider,
			GitHubOrgId:           model.GitHubOrgId,
			GitLabGroupId:         model.GitLabGroupId,
			Active:                model.Active,
			Token:                 model.Token,
			Host:                  model.Host,
			Username:              model.Username,
			UserId:                model.CreatedBy,
			AzureProjectName:      model.AzureProject,
			BitBucketWorkspaceId:  model.BitBucketWorkspaceId,
			BitBucketProjectKey:   model.BitBucketProjectKey,
			AllowCustomRepository: model.AllowCustomRepository,
			TLSConfig: &bean3.TLSConfig{
				CaData:      model.CaCert,
				TLSCertData: model.TlsCert,
				TLSKeyData:  model.TlsKey,
			},
			EnableTLSVerification: model.EnableTLSVerification,
		})
	}
	return configs, err
}

func (impl *GitOpsConfigReadServiceImpl) GetConfiguredGitOpsCount() (int, error) {
	count, err := impl.gitOpsRepository.GetAllGitOpsConfigCount()
	return count, err
}

func (impl *GitOpsConfigReadServiceImpl) GetGitOpsProviderByRepoURL(gitRepoUrl string) (*bean2.GitOpsConfigDto, error) {

	if gitRepoUrl == bean2.GIT_REPO_NOT_CONFIGURED {
		model, err := impl.GetGitOpsConfigActive()
		if err != nil {
			impl.logger.Errorw("error in getting default gitOps provider", "err", err)
			return nil, err
		}
		return model, nil
	}

	models, err := impl.gitOpsRepository.GetAllGitOpsConfig()
	if err != nil {
		impl.logger.Errorw("error, GetGitOpsConfigActive", "err", err)
		return nil, err
	}

	inputHostURL, inputScheme, err := util.GetHost(gitRepoUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to parse host from repo URL: %s", gitRepoUrl)
	}

	for _, model := range models {
		configBean := adapter.GetGitOpsConfigBean(model)
		hostURL, scheme, err := util.GetHost(configBean.GetHostUrl())
		if err != nil {
			return nil, fmt.Errorf("unable to parse host from repo URL: %s", gitRepoUrl)
		}
		if len(hostURL) > 0 && len(inputHostURL) > 0 &&
			strings.HasPrefix(inputHostURL, hostURL) &&
			scheme == inputScheme {
			// written with assumption that only one GitOpsConfig is present in DB for each provider(github, gitlab, etc)
			return configBean, nil
		}
	}

	errMsg := fmt.Sprintf("no gitops config found in DB for given repository: %q", gitRepoUrl)
	return nil, internalUtil.NewApiError(http.StatusBadRequest, errMsg, errMsg).
		WithCode(constants.GitOpsNotConfigured)
}

func (impl *GitOpsConfigReadServiceImpl) GetGitOpsById(id int) (*bean2.GitOpsConfigDto, error) {
	model, err := impl.gitOpsRepository.GetGitOpsConfigById(id)
	if err != nil {
		impl.logger.Errorw("error, GetGitOpsConfigById", "id", id, "err", err)
		return nil, err
	}
	return adapter.GetGitOpsConfigBean(model), err
}

func (impl *GitOpsConfigReadServiceImpl) GetGitConfig() (*gitBean.GitConfig, error) {
	gitOpsConfig, err := impl.GetGitOpsConfigActive()
	if err != nil {
		impl.logger.Errorw("error while fetching gitops config", "err", err)
		return nil, err
	}
	return gitAdapter.ConvertGitOpsConfigToGitConfig(gitOpsConfig), err
}
