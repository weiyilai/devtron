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

package k8s

import (
	"errors"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/devtron-labs/common-lib/utils"
	"github.com/devtron-labs/common-lib/utils/k8sObjectsUtil"
	"github.com/devtron-labs/common-lib/utils/remoteConnection/bean"
	v1 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

type ClusterConfig struct {
	ClusterName                     string
	Host                            string
	BearerToken                     string
	InsecureSkipTLSVerify           bool
	KeyData                         string
	CertData                        string
	CAData                          string
	ClusterId                       int
	ToConnectForClusterVerification bool
	RemoteConnectionConfig          *bean.RemoteConnectionConfigBean
}

var logger, _ = utils.NewSugardLogger()

func (clusterConfig *ClusterConfig) PopulateTlsConfigurationsInto(restConfig *rest.Config) {
	serverName, err := GetServerNameFromServerUrl(clusterConfig.Host)
	if err != nil {
		// making it non-blocking to avoid blocking the flow
		logger.Errorw("Error parsing server URL:", "err", err, "clusterConfig.Host", clusterConfig.Host)
	}
	restConfig.TLSClientConfig = rest.TLSClientConfig{Insecure: clusterConfig.InsecureSkipTLSVerify, ServerName: serverName}
	if clusterConfig.InsecureSkipTLSVerify == false {
		restConfig.TLSClientConfig.KeyData = []byte(clusterConfig.KeyData)
		restConfig.TLSClientConfig.CertData = []byte(clusterConfig.CertData)
		restConfig.TLSClientConfig.CAData = []byte(clusterConfig.CAData)
	}
}

type ClusterResourceListMap struct {
	Headers       []string                 `json:"headers"`
	Data          []map[string]interface{} `json:"data"`
	ServerVersion string                   `json:"serverVersion"`
}

type EventsResponse struct {
	Events *v1.EventList `json:"events,omitempty"`
}

type ResourceListResponse struct {
	Resources unstructured.UnstructuredList `json:"resources,omitempty"`
}

type PodLogsRequest struct {
	SinceTime                  *v12.Time `json:"sinceTime,omitempty"`
	SinceSeconds               int       `json:"sinceSeconds,omitempty"`
	TailLines                  int       `json:"tailLines"`
	Follow                     bool      `json:"follow"`
	ContainerName              string    `json:"containerName"`
	IsPrevContainerLogsEnabled bool      `json:"previous"`
}

type ResourceIdentifier struct {
	Name             string                  `json:"name"` //pod name for logs request
	Namespace        string                  `json:"namespace"`
	GroupVersionKind schema.GroupVersionKind `json:"groupVersionKind"`
}

type K8sRequestBean struct {
	ResourceIdentifier ResourceIdentifier `json:"resourceIdentifier"`
	Patch              string             `json:"patch,omitempty"`
	PodLogsRequest     PodLogsRequest     `json:"podLogsRequest,omitempty"`
	ForceDelete        bool               `json:"forceDelete,omitempty"`
}

type GetAllApiResourcesResponse struct {
	ApiResources []*K8sApiResource `json:"apiResources"`
	AllowedAll   bool              `json:"allowedAll"`
}

type K8sApiResource struct {
	Gvk        schema.GroupVersionKind     `json:"gvk"`
	Gvr        schema.GroupVersionResource `json:"gvr"`
	Namespaced bool                        `json:"namespaced"`
	ShortNames []string                    `json:"shortNames"`
}

type ApplyResourcesRequest struct {
	Manifest  string `json:"manifest"`
	ClusterId int    `json:"clusterId"`
}

type ApplyResourcesResponse struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Error    string `json:"error"`
	IsUpdate bool   `json:"isUpdate"`
}

type ManifestResponse struct {
	Manifest            unstructured.Unstructured  `json:"manifest,omitempty"`
	RecommendedManifest *unstructured.Unstructured `json:"recommendedManifest,omitempty"` // imp: this is used to show recommended resources for the resource browser
	// EphemeralContainers are set for Pod kind manifest response only.
	// will only contain ephemeral containers which are in running state
	// +optional
	EphemeralContainers []*k8sObjectsUtil.EphemeralContainerData `json:"ephemeralContainers,omitempty"`
}

// SetRunningEphemeralContainers will extract out all the running ephemeral containers of the given pod manifest and sets in manifestResponse.EphemeralContainers
// if given manifest is not of pod kind
func (manifestResponse *ManifestResponse) SetRunningEphemeralContainers() error {
	if manifestResponse != nil {
		if podManifest := manifestResponse.Manifest; k8sObjectsUtil.IsPod(podManifest.GetKind(), podManifest.GroupVersionKind().Group) {
			pod := v1.Pod{}
			// Convert the unstructured object to a Pod object
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(podManifest.Object, &pod)
			if err != nil {
				return err
			}
			runningEphemeralContainers := k8sObjectsUtil.ExtractEphemeralContainers([]v1.Pod{pod})
			manifestResponse.EphemeralContainers = runningEphemeralContainers[pod.Name]
		}
	}
	return nil
}

type ResourceKey struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
}

func (k *ResourceKey) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", k.Group, k.Kind, k.Namespace, k.Name)
}

func (k ResourceKey) GroupKind() schema.GroupKind {
	return schema.GroupKind{Group: k.Group, Kind: k.Kind}
}

func NewResourceKey(group string, kind string, namespace string, name string) ResourceKey {
	return ResourceKey{Group: group, Kind: kind, Namespace: namespace, Name: name}
}

func GetResourceKey(obj *unstructured.Unstructured) ResourceKey {
	gvk := obj.GroupVersionKind()
	return NewResourceKey(gvk.Group, gvk.Kind, obj.GetNamespace(), obj.GetName())
}

type LocalDevMode bool

type RuntimeConfig struct {
	LocalDevMode LocalDevMode `env:"RUNTIME_CONFIG_LOCAL_DEV" envDefault:"false"`
}

func GetRuntimeConfig() (*RuntimeConfig, error) {
	cfg := &RuntimeConfig{}
	err := env.Parse(cfg)
	return cfg, err
}

var NotFoundError = errors.New("not found")

func IsNotFoundError(err error) bool {
	return errors.Is(err, NotFoundError)
}

type JsonPatchType struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}
