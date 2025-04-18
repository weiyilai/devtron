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

package bean

const (
	GitOpsCommitDefaultEmailId = "devtron-bot@devtron.ai"
	GitOpsCommitDefaultName    = "devtron bot"
)

// TODO: remove below object and its related methods to eliminate provider specific signature
type BitbucketProviderMetadata struct {
	BitBucketWorkspaceId string
	BitBucketProjectKey  string
}

const BITBUCKET_PROVIDER = "BITBUCKET_CLOUD"

type GitOpsConfigurationStatus struct {
	IsGitOpsConfigured    bool
	IsArgoCdInstalled     bool
	AllowCustomRepository bool
	Provider              string
}

func (g *GitOpsConfigurationStatus) IsGitOpsConfiguredAndArgoCdInstalled() bool {
	return g.IsGitOpsConfigured && g.IsArgoCdInstalled
}
