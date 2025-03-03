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

package notifier

import (
	"fmt"
	"github.com/devtron-labs/devtron/pkg/notifier/adapter"
	"github.com/devtron-labs/devtron/pkg/notifier/beans"
	"testing"

	"github.com/devtron-labs/devtron/internal/sql/repository"
	mocks2 "github.com/devtron-labs/devtron/internal/sql/repository/mocks"
	util2 "github.com/devtron-labs/devtron/internal/util"
	"github.com/devtron-labs/devtron/pkg/team/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

func Test_buildWebhookNewConfigs(t *testing.T) {
	type args struct {
		webhookReq []beans.WebhookConfigDto
		userId     int32
	}
	tests := []struct {
		name string
		args args
		want []*repository.WebhookConfig
	}{
		{
			name: "test1",
			args: args{
				webhookReq: []beans.WebhookConfigDto{
					{
						WebhookUrl: "dfcd nmc dc",
						ConfigName: "aditya",
						Payload:    "{\"text\": \"final\"}",
						Header:     map[string]interface{}{"Content-type": "application/json"},
					},
				},
				userId: 1,
			},
			want: []*repository.WebhookConfig{
				{
					WebHookUrl: "dfcd nmc dc",
					ConfigName: "aditya",
					Payload:    "{\"text\": \"final\"}",
					Header:     map[string]interface{}{"Content-type": "application/json"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := adapter.BuildWebhookNewConfigs(tt.args.webhookReq, tt.args.userId)

			assert.Equal(t, len(tt.want), len(got), "Number of webhook configs mismatch")

			for i, want := range tt.want {
				assert.Equal(t, want.WebHookUrl, got[i].WebHookUrl, "WebHookUrl mismatch")
				assert.Equal(t, want.ConfigName, got[i].ConfigName, "ConfigName mismatch")
				assert.Equal(t, want.Payload, got[i].Payload, "Payload mismatch")
				assert.Equal(t, want.Header, got[i].Header, "Header mismatch")

			}
		})
	}
}

func TestWebhookNotificationServiceImpl_SaveOrEditNotificationConfig(t *testing.T) {
	sugaredLogger, err := util2.NewSugardLogger()
	assert.Nil(t, err)
	mockedTeamService := mocks.NewTeamService(t)
	mockedWebhookNotfRep := mocks2.NewWebhookNotificationRepository(t)
	//mockedUserRepo := mocks3.NewUserRepository(t)
	mockedNotfSetRepo := mocks2.NewNotificationSettingsRepository(t)

	type args struct {
		channelReq []beans.WebhookConfigDto
		userId     int32
	}

	tests := []struct {
		name    string
		args    args
		want    []int
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "SaveOrUpdate_ExistingConfig",
			args: args{
				channelReq: []beans.WebhookConfigDto{
					{
						WebhookUrl: "djfndgfbd,gds",
						ConfigName: "aditya",
						Payload:    "{\"text\": \"final\"}",
						Header:     map[string]interface{}{"Content-type": "application/json"},
					},
				},
				userId: 2,
			},
			want:    []int{0},
			wantErr: assert.NoError,
		},
		{
			name: "SaveOrUpdate_NewConfig",
			args: args{
				channelReq: []beans.WebhookConfigDto{
					{
						WebhookUrl: "d,fm sdfd",
						ConfigName: "aditya",
						Payload:    "{\"text\": \"final\"}",
						Header:     map[string]interface{}{"Content-type": "application/json"},
					},
				},
				userId: 2,
			},
			want:    []int{0},
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impl := &WebhookNotificationServiceImpl{
				logger:                         sugaredLogger,
				webhookRepository:              mockedWebhookNotfRep,
				teamService:                    mockedTeamService,
				userRepository:                 nil,
				notificationSettingsRepository: mockedNotfSetRepo,
			}

			mockConfig := &repository.WebhookConfig{Id: 1}
			mockError := error(nil)
			mockedWebhookNotfRep.On("SaveWebhookConfig", mock.Anything).Return(mockConfig, mockError)

			got, err := impl.SaveOrEditNotificationConfig(tt.args.channelReq, tt.args.userId)

			if !tt.wantErr(t, err, fmt.Sprintf("SaveOrEditNotificationConfig(%v, %v)", tt.args.channelReq, tt.args.userId)) {
				return
			}
			assert.Equalf(t, tt.want, got, "SaveOrEditNotificationConfig(%v, %v)", tt.args.channelReq, tt.args.userId)
		})
	}
}
