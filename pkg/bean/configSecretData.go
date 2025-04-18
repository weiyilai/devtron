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

import (
	"encoding/json"
	"github.com/devtron-labs/devtron/util"
	"strings"
)

type ConfigList struct {
	ConfigData []*ConfigData `json:"maps"`
}

type SecretList struct {
	ConfigData []*ConfigData `json:"secrets"`
}

// there is an adapter written in pkg/bean folder to convert below ConfigData struct to pipeline/bean's ConfigData

// TODO refactoring: duplicate struct of ConfigData in ConfigMapBean.go
type ConfigData struct {
	Name                  string           `json:"name"`
	Type                  string           `json:"type"`
	External              bool             `json:"external"`
	MountPath             string           `json:"mountPath,omitempty"`
	Data                  json.RawMessage  `json:"data"`
	DefaultData           json.RawMessage  `json:"defaultData,omitempty"`
	DefaultMountPath      string           `json:"defaultMountPath,omitempty"`
	Global                bool             `json:"global"`
	ExternalSecretType    string           `json:"externalType"`
	ExternalSecret        []ExternalSecret `json:"secretData"`
	DefaultExternalSecret []ExternalSecret `json:"defaultSecretData,omitempty"`
	ESOSecretData         ESOSecretData    `json:"esoSecretData"`
	DefaultESOSecretData  ESOSecretData    `json:"defaultESOSecretData,omitempty"`
	RoleARN               string           `json:"roleARN"`
	SubPath               bool             `json:"subPath"`
	ESOSubPath            []string         `json:"esoSubPath"`
	FilePermission        string           `json:"filePermission"`
	Overridden            bool             `json:"overridden"`
}

func (c *ConfigData) IsESOExternalSecretType() bool {
	return strings.HasPrefix(c.ExternalSecretType, "ESO")
}

type ExternalSecret struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Property string `json:"property,omitempty"`
	IsBinary bool   `json:"isBinary"`
}

type ESOSecretData struct {
	SecretStore     json.RawMessage `json:"secretStore,omitempty"`
	SecretStoreRef  json.RawMessage `json:"secretStoreRef,omitempty"`
	ESOData         []ESOData       `json:"esoData"`
	RefreshInterval string          `json:"refreshInterval,omitempty"`
	ESODataFrom     json.RawMessage `json:"esoDataFrom,omitempty"`
	Template        json.RawMessage `json:"template,omitempty"`
}

type ESOData struct {
	SecretKey string `json:"secretKey"`
	Key       string `json:"key"`
	Property  string `json:"property,omitempty"`
}

func GetTransformedDataForSecretConfigData(data string, mode util.SecretTransformMode) (string, error) {
	secretDataMap := make(map[string]*ConfigData)
	err := json.Unmarshal([]byte(data), &secretDataMap)
	if err != nil {
		return "", err
	}

	for _, configData := range secretDataMap {
		if configData.Data == nil || configData.External {
			continue
		}
		data, err := util.GetDecodedAndEncodedData(configData.Data, mode)
		if err != nil {
			return "", err
		}
		configData.Data = data

	}
	resolvedTemplate, err := json.Marshal(secretDataMap)
	if err != nil {
		return "", err
	}
	return string(resolvedTemplate), nil
}

func (SecretList) GetTransformedDataForSecret(data string, mode util.SecretTransformMode) (string, error) {
	secretsList := SecretList{}
	err := json.Unmarshal([]byte(data), &secretsList)
	if err != nil {
		return "", err
	}

	for _, configData := range secretsList.ConfigData {
		if configData.Data == nil || configData.External {
			continue
		}
		configData.Data, err = util.GetDecodedAndEncodedData(configData.Data, mode)
		if err != nil {
			return "", err
		}
	}

	marshal, err := json.Marshal(secretsList)
	if err != nil {
		return "", err
	}
	return string(marshal), nil
}
