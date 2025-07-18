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

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devtron-labs/common-lib/utils"
	"github.com/devtron-labs/devtron/api/helm-app/gRPC"
	client "github.com/devtron-labs/devtron/api/helm-app/service"
	"github.com/devtron-labs/devtron/api/helm-app/service/bean"
	"github.com/devtron-labs/devtron/pkg/argoApplication/helper"
	"github.com/devtron-labs/devtron/pkg/auth/authorisation/casbin"
	bean5 "github.com/devtron-labs/devtron/pkg/cluster/environment/bean"
	"github.com/devtron-labs/devtron/pkg/cluster/read"
	clientErrors "github.com/devtron-labs/devtron/pkg/errors"
	"github.com/devtron-labs/devtron/pkg/fluxApplication"
	bean2 "github.com/devtron-labs/devtron/pkg/fluxApplication/bean"
	bean4 "github.com/devtron-labs/devtron/pkg/k8s/bean"
	"io"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"net/http"
	"strconv"
	"strings"

	"github.com/caarlos0/env/v6"
	k8s2 "github.com/devtron-labs/common-lib/utils/k8s"
	k8sCommonBean "github.com/devtron-labs/common-lib/utils/k8s/commonBean"
	k8sObjectUtils "github.com/devtron-labs/common-lib/utils/k8sObjectsUtil"
	"github.com/devtron-labs/devtron/internal/util"

	yamlUtil "github.com/devtron-labs/common-lib/utils/yaml"
	"github.com/devtron-labs/devtron/api/connector"
	"github.com/devtron-labs/devtron/api/helm-app/openapiClient"
	"github.com/devtron-labs/devtron/pkg/cluster"
	"github.com/devtron-labs/devtron/pkg/cluster/repository"
	"github.com/devtron-labs/devtron/pkg/k8s"
	bean3 "github.com/devtron-labs/devtron/pkg/k8s/application/bean"
	"github.com/devtron-labs/devtron/pkg/kubernetesResourceAuditLogs"
	"github.com/devtron-labs/devtron/pkg/terminal"
	util3 "github.com/devtron-labs/devtron/pkg/util"
	util2 "github.com/devtron-labs/devtron/util"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type K8sApplicationService interface {
	ValidatePodLogsRequestQuery(r *http.Request) (*bean4.ResourceRequestBean, error)
	ValidateTerminalRequestQuery(r *http.Request) (*terminal.TerminalSessionRequest, *bean4.ResourceRequestBean, error)
	DecodeDevtronAppId(applicationId string) (*bean3.DevtronAppIdentifier, error)
	GetPodLogs(ctx context.Context, request *bean4.ResourceRequestBean) (io.ReadCloser, error)
	ValidateResourceRequest(ctx context.Context, appIdentifier *bean.AppIdentifier, request *k8s2.K8sRequestBean) error
	ValidateClusterResourceRequest(ctx context.Context, clusterResourceRequest *bean4.ResourceRequestBean,
		rbacCallback func(clusterName string, resourceIdentifier k8s2.ResourceIdentifier) bool) (bool, error)
	ValidateClusterResourceBean(ctx context.Context, clusterId int, manifest unstructured.Unstructured, gvk schema.GroupVersionKind, rbacCallback func(clusterName string, resourceIdentifier k8s2.ResourceIdentifier) bool) bool
	GetResourceInfo(ctx context.Context) (*bean3.ResourceInfo, error)
	GetAllApiResourceGVKWithoutAuthorization(ctx context.Context, clusterId int) (*k8s2.GetAllApiResourcesResponse, error)
	GetAllApiResources(ctx context.Context, clusterId int, isSuperAdmin bool, userId int32) (*k8s2.GetAllApiResourcesResponse, error)
	GetResourceList(ctx context.Context, token string, request *bean4.ResourceRequestBean, validateResourceAccess func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool) (*k8s2.ClusterResourceListMap, error)
	GetResourceListWithRestConfig(ctx context.Context, token string, request *bean4.ResourceRequestBean, validateResourceAccess func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool,
		restConfig *rest.Config, clusterName string) (*k8s2.ClusterResourceListMap, error)
	ApplyResources(ctx context.Context, token string, request *k8s2.ApplyResourcesRequest, resourceRbacHandler func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool) ([]*k8s2.ApplyResourcesResponse, error)
	CreatePodEphemeralContainers(req *bean5.EphemeralContainerRequest) error
	TerminatePodEphemeralContainer(req bean5.EphemeralContainerRequest) (bool, error)
	GetPodContainersList(clusterId int, namespace, podName string) (*bean4.PodContainerList, error)
	GetPodListByLabel(clusterId int, namespace, label string) ([]corev1.Pod, error)
	RecreateResource(ctx context.Context, request *bean4.ResourceRequestBean) (*k8s2.ManifestResponse, error)
	DeleteResourceWithAudit(ctx context.Context, request *bean4.ResourceRequestBean, userId int32) (*k8s2.ManifestResponse, error)
	GetUrlsByBatchForIngress(ctx context.Context, resp []bean4.BatchResourceResponse) []interface{}
	ValidateFluxResourceRequest(ctx context.Context, appIdentifier *bean2.FluxAppIdentifier, request *k8s2.K8sRequestBean) (bool, error)
}

type K8sApplicationServiceImpl struct {
	logger                       *zap.SugaredLogger
	clusterService               cluster.ClusterService
	pump                         connector.Pump
	helmAppService               client.HelmAppService
	K8sUtil                      *k8s2.K8sServiceImpl
	aCDAuthConfig                *util3.ACDAuthConfig
	K8sResourceHistoryService    kubernetesResourceAuditLogs.K8sResourceHistoryService
	k8sCommonService             k8s.K8sCommonService
	terminalSession              terminal.TerminalSessionHandler
	ephemeralContainerService    cluster.EphemeralContainerService
	ephemeralContainerRepository repository.EphemeralContainersRepository
	ephemeralContainerConfig     *EphemeralContainerConfig
	fluxApplicationService       fluxApplication.FluxApplicationService
	clusterReadService           read.ClusterReadService
}

func NewK8sApplicationServiceImpl(Logger *zap.SugaredLogger, clusterService cluster.ClusterService, pump connector.Pump, helmAppService client.HelmAppService, K8sUtil *k8s2.K8sServiceImpl, aCDAuthConfig *util3.ACDAuthConfig, K8sResourceHistoryService kubernetesResourceAuditLogs.K8sResourceHistoryService,
	k8sCommonService k8s.K8sCommonService, terminalSession terminal.TerminalSessionHandler,
	ephemeralContainerService cluster.EphemeralContainerService,
	ephemeralContainerRepository repository.EphemeralContainersRepository,
	fluxApplicationService fluxApplication.FluxApplicationService,
	clusterReadService read.ClusterReadService) (*K8sApplicationServiceImpl, error) {
	ephemeralContainerConfig := &EphemeralContainerConfig{}
	err := env.Parse(ephemeralContainerConfig)
	if err != nil {
		Logger.Errorw("error in parsing EphemeralContainerConfig from env", "err", err)
		return nil, err
	}
	return &K8sApplicationServiceImpl{
		logger:                       Logger,
		clusterService:               clusterService,
		pump:                         pump,
		helmAppService:               helmAppService,
		K8sUtil:                      K8sUtil,
		aCDAuthConfig:                aCDAuthConfig,
		K8sResourceHistoryService:    K8sResourceHistoryService,
		k8sCommonService:             k8sCommonService,
		terminalSession:              terminalSession,
		ephemeralContainerService:    ephemeralContainerService,
		ephemeralContainerRepository: ephemeralContainerRepository,
		ephemeralContainerConfig:     ephemeralContainerConfig,
		//argoApplicationService:       argoApplicationService,
		fluxApplicationService: fluxApplicationService,
		clusterReadService:     clusterReadService,
	}, nil
}

type EphemeralContainerConfig struct {
	EphemeralServerVersionRegex string `env:"EPHEMERAL_SERVER_VERSION_REGEX" envDefault:"v[1-9]\\.\\b(2[3-9]|[3-9][0-9])\\b.*" description:"ephemeral containers support version regex that is compared with k8sServerVersion"`
}

func (impl *K8sApplicationServiceImpl) ValidatePodLogsRequestQuery(r *http.Request) (*bean4.ResourceRequestBean, error) {
	v, vars := r.URL.Query(), mux.Vars(r)
	request := &bean4.ResourceRequestBean{}
	var err error
	request.ExternalArgoApplicationName = v.Get("externalArgoApplicationName")
	appTypeStr := v.Get("appType")
	var appType int
	if len(appTypeStr) > 0 {
		appType, err = strconv.Atoi(appTypeStr)
		if err != nil {
			return nil, &util.ApiError{
				Code:            "400",
				HttpStatusCode:  400,
				UserMessage:     "invalid param: appType",
				InternalMessage: "invalid param: appType",
			}
		}
	}
	request.AppType = appType
	podName := vars["podName"]
	sinceSecondsParam := v.Get("sinceSeconds")
	var sinceSeconds int
	if len(sinceSecondsParam) > 0 {
		sinceSeconds, err = strconv.Atoi(sinceSecondsParam)
		if err != nil || sinceSeconds <= 0 {
			return nil, &util.ApiError{
				Code:            "400",
				HttpStatusCode:  400,
				UserMessage:     "invalid value provided for sinceSeconds",
				InternalMessage: "invalid value provided for sinceSeconds"}
		}
	}
	sinceTimeParam := v.Get("sinceTime")
	sinceTime := metav1.Unix(0, 0)
	if len(sinceTimeParam) > 0 {
		sinceTimeVar, err := strconv.ParseInt(sinceTimeParam, 10, 64)
		if err != nil || sinceTimeVar <= 0 {
			return nil, &util.ApiError{
				Code:            "400",
				HttpStatusCode:  400,
				UserMessage:     "invalid value provided for sinceTime",
				InternalMessage: "invalid value provided for sinceTime"}
		}
		sinceTime = metav1.Unix(sinceTimeVar, 0)
	}

	namespace := v.Get("namespace")
	if namespace == "" {
		err = fmt.Errorf("missing required field namespace")
		impl.logger.Errorw("empty namespace", "err", err, "appId", request.AppId)
		return nil, err
	}
	containerName, clusterIdString := v.Get("containerName"), v.Get("clusterId")
	prevContainerLogs := v.Get("previous")
	isPrevLogs, err := strconv.ParseBool(prevContainerLogs)
	if err != nil {
		isPrevLogs = false
	}
	appId := v.Get("appId")
	follow, err := strconv.ParseBool(v.Get("follow"))
	if err != nil {
		follow = false
	}
	tailLinesParam := v.Get("tailLines")
	var tailLines int
	if len(tailLinesParam) > 0 {
		tailLines, err = strconv.Atoi(tailLinesParam)
		if err != nil || tailLines <= 0 {
			return nil, &util.ApiError{
				Code:            "400",
				HttpStatusCode:  400,
				UserMessage:     "invalid value provided for tailLines",
				InternalMessage: "invalid value provided for tailLines"}
		}
	}
	k8sRequest := &k8s2.K8sRequestBean{
		ResourceIdentifier: k8s2.ResourceIdentifier{
			Name:             podName,
			GroupVersionKind: schema.GroupVersionKind{},
		},
		PodLogsRequest: k8s2.PodLogsRequest{
			SinceSeconds:               sinceSeconds,
			SinceTime:                  &sinceTime,
			TailLines:                  tailLines,
			Follow:                     follow,
			ContainerName:              containerName,
			IsPrevContainerLogsEnabled: isPrevLogs,
		},
	}
	request.K8sRequest = k8sRequest
	if appId != "" {
		if len(appTypeStr) > 0 && !request.IsValidAppType() {
			impl.logger.Errorw("Invalid appType", "err", err, "appType", appType)
			return nil, err
		}
		// Validate Deployment Type
		deploymentType, err := strconv.Atoi(v.Get("deploymentType"))
		if err != nil || !request.IsValidDeploymentType() {
			impl.logger.Errorw("Invalid deploymentType", "err", err, "deploymentType", deploymentType)
			return nil, err
		}

		//handle the ns coming for the requested resource
		request.DeploymentType = deploymentType
		// Validate App Id
		if request.AppType == bean3.ArgoAppType {
			appIdentifier, err := helper.DecodeExternalArgoAppId(appId)
			if err != nil {
				impl.logger.Errorw(bean3.AppIdDecodingError, "err", err, "appId", appId)
				return nil, err
			}

			request.ClusterId = appIdentifier.ClusterId
			request.K8sRequest.ResourceIdentifier.Namespace = namespace
			request.AppId = appId
			request.ExternalArgoAppIdentifier = appIdentifier
		} else if request.AppType == bean3.HelmAppType {
			// For Helm App resources
			appIdentifier, err := impl.helmAppService.DecodeAppId(appId)
			if err != nil {
				impl.logger.Errorw(bean3.AppIdDecodingError, "err", err, "appId", appId)
				return nil, err
			}
			request.AppIdentifier = appIdentifier
			request.ClusterId = appIdentifier.ClusterId
			request.K8sRequest.ResourceIdentifier.Namespace = namespace
		} else if request.AppType == bean3.DevtronAppType {
			// For Devtron App resources
			devtronAppIdentifier, err := impl.DecodeDevtronAppId(appId)
			if err != nil {
				impl.logger.Errorw(bean3.AppIdDecodingError, "err", err, "appId", request.AppId)
				return nil, err
			}
			request.DevtronAppIdentifier = devtronAppIdentifier
			request.ClusterId = devtronAppIdentifier.ClusterId
			request.K8sRequest.ResourceIdentifier.Namespace = namespace
		} else if request.AppType == bean3.FluxAppType {
			// For flux App resources
			appIdentifier, err := fluxApplication.DecodeFluxExternalAppId(appId)
			if err != nil {
				impl.logger.Errorw(bean3.AppIdDecodingError, "err", err, "appId", appId)
				return nil, err
			}
			request.ExternalFluxAppIdentifier = appIdentifier
			request.ClusterId = appIdentifier.ClusterId
			request.K8sRequest.ResourceIdentifier.Namespace = namespace
		}
	} else if clusterIdString != "" {
		// Validate Cluster Id
		clusterId, err := strconv.Atoi(clusterIdString)
		if err != nil {
			impl.logger.Errorw("invalid cluster id", "clusterId", clusterIdString, "err", err)
			return nil, err
		}
		request.ClusterId = clusterId
		request.K8sRequest.ResourceIdentifier.Namespace = namespace
		request.K8sRequest.ResourceIdentifier.GroupVersionKind = schema.GroupVersionKind{
			Group:   "",
			Kind:    "Pod",
			Version: "v1",
		}
	}
	return request, nil
}

func (impl *K8sApplicationServiceImpl) ValidateTerminalRequestQuery(r *http.Request) (*terminal.TerminalSessionRequest, *bean4.ResourceRequestBean, error) {
	request := &terminal.TerminalSessionRequest{}
	v := r.URL.Query()
	vars := mux.Vars(r)
	request.ContainerName = vars["container"]
	request.Namespace = vars["namespace"]
	request.PodName = vars["pod"]
	request.Shell = vars["shell"]
	resourceRequestBean := &bean4.ResourceRequestBean{}
	identifier := vars["identifier"]
	if strings.Contains(identifier, "|") {
		// Validate App Type
		appType, err := strconv.Atoi(v.Get("appType"))
		resourceRequestBean.AppType = appType
		if err != nil || !resourceRequestBean.IsValidAppType() {
			impl.logger.Errorw("Invalid appType", "err", err, "appType", appType)
			return nil, nil, err
		}
		request.ApplicationId = identifier

		if appType == bean3.HelmAppType {
			appIdentifier, err := impl.helmAppService.DecodeAppId(request.ApplicationId)
			if err != nil {
				impl.logger.Errorw(bean3.InvalidAppId, "err", err, "appId", request.ApplicationId)
				return nil, nil, err
			}
			resourceRequestBean.AppIdentifier = appIdentifier
			resourceRequestBean.ClusterId = appIdentifier.ClusterId
			request.ClusterId = appIdentifier.ClusterId
		} else if appType == bean3.DevtronAppType {
			devtronAppIdentifier, err := impl.DecodeDevtronAppId(request.ApplicationId)
			if err != nil {
				impl.logger.Errorw(bean3.InvalidAppId, "err", err, "appId", request.ApplicationId)
				return nil, nil, err
			}
			resourceRequestBean.DevtronAppIdentifier = devtronAppIdentifier
			resourceRequestBean.ClusterId = devtronAppIdentifier.ClusterId
			request.ClusterId = devtronAppIdentifier.ClusterId
		} else if appType == bean3.FluxAppType {
			fluxAppIdentifier, err := fluxApplication.DecodeFluxExternalAppId(request.ApplicationId)
			if err != nil {
				impl.logger.Errorw(bean3.InvalidAppId, "err", err, "appId", request.ApplicationId)
				return nil, nil, err
			}
			resourceRequestBean.ExternalFluxAppIdentifier = fluxAppIdentifier
			resourceRequestBean.ClusterId = fluxAppIdentifier.ClusterId
			request.ClusterId = fluxAppIdentifier.ClusterId

		} else if appType == bean3.ArgoAppType {
			appIdentifier, err := helper.DecodeExternalArgoAppId(request.ApplicationId)
			if err != nil {
				impl.logger.Errorw(bean3.InvalidAppId, "err", err, "appId", request.ApplicationId)
				return nil, nil, err
			}
			resourceRequestBean.ExternalArgoApplicationName = appIdentifier.AppName
			resourceRequestBean.ClusterId = appIdentifier.ClusterId
			request.ClusterId = appIdentifier.ClusterId
			request.ExternalArgoApplicationName = appIdentifier.AppName
			request.ExternalArgoApplicationNamespace = appIdentifier.Namespace
			request.ExternalArgoAppIdentifier = appIdentifier
		}
	} else {
		// Validate Cluster Id
		clusterId, err := strconv.Atoi(identifier)
		if err != nil || clusterId <= 0 {
			impl.logger.Errorw("Invalid cluster id", "err", err, "clusterId", identifier)
			return nil, nil, err
		}
		resourceRequestBean.ClusterId = clusterId
		request.ClusterId = clusterId
		k8sRequest := &k8s2.K8sRequestBean{
			ResourceIdentifier: k8s2.ResourceIdentifier{
				Name:      request.PodName,
				Namespace: request.Namespace,
				GroupVersionKind: schema.GroupVersionKind{
					Group:   "",
					Kind:    "Pod",
					Version: "v1",
				},
			},
		}
		resourceRequestBean.K8sRequest = k8sRequest
	}
	return request, resourceRequestBean, nil
}

func (impl *K8sApplicationServiceImpl) DecodeDevtronAppId(applicationId string) (*bean3.DevtronAppIdentifier, error) {
	component := strings.Split(applicationId, "|")
	if len(component) != 3 {
		return nil, fmt.Errorf("malformed app id %s", applicationId)
	}
	clusterId, err := strconv.Atoi(component[0])
	if err != nil {
		return nil, err
	}
	appId, err := strconv.Atoi(component[1])
	if err != nil {
		return nil, err
	}
	envId, err := strconv.Atoi(component[2])
	if err != nil {
		return nil, err
	}
	if clusterId <= 0 || appId <= 0 || envId <= 0 {
		return nil, fmt.Errorf("invalid app identifier")
	}
	return &bean3.DevtronAppIdentifier{
		ClusterId: clusterId,
		AppId:     appId,
		EnvId:     envId,
	}, nil
}

func (impl *K8sApplicationServiceImpl) GetPodLogs(ctx context.Context, request *bean4.ResourceRequestBean) (io.ReadCloser, error) {
	clusterId := request.ClusterId
	resourceIdentifier := request.K8sRequest.ResourceIdentifier
	podLogsRequest := request.K8sRequest.PodLogsRequest

	restConfig, err := impl.k8sCommonService.GetRestConfigOfCluster(ctx, request)
	if err != nil {
		impl.logger.Errorw("error in getting rest config by clusterId", "err", err, "clusterId", clusterId, "")
		return nil, err
	}
	resp, err := impl.K8sUtil.GetPodLogs(ctx, restConfig, resourceIdentifier.Name, resourceIdentifier.Namespace, podLogsRequest.SinceTime, podLogsRequest.TailLines, podLogsRequest.SinceSeconds, podLogsRequest.Follow, podLogsRequest.ContainerName, podLogsRequest.IsPrevContainerLogsEnabled)
	if err != nil {
		impl.logger.Errorw("error in getting pod logs", "err", err, "clusterId", clusterId)
		return nil, err
	}
	return resp, nil
}

func (impl *K8sApplicationServiceImpl) ValidateClusterResourceRequest(ctx context.Context, clusterResourceRequest *bean4.ResourceRequestBean,
	rbacCallback func(clusterName string, resourceIdentifier k8s2.ResourceIdentifier) bool) (bool, error) {
	clusterId := clusterResourceRequest.ClusterId
	clusterBean, err := impl.clusterReadService.FindById(clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting clusterBean by cluster Id", "clusterId", clusterId, "err", err)
		return false, err
	}
	clusterName := clusterBean.ClusterName
	k8sRequest := clusterResourceRequest.K8sRequest
	respManifest, err := impl.k8sCommonService.GetResource(ctx, clusterResourceRequest)
	if err != nil {
		impl.logger.Errorw("error in getting resource", "err", err, "request", clusterResourceRequest)
		return false, err
	}
	return impl.validateResourceManifest(clusterName, respManifest.ManifestResponse.Manifest, k8sRequest.ResourceIdentifier.GroupVersionKind, rbacCallback), nil
}

func (impl *K8sApplicationServiceImpl) validateResourceManifest(clusterName string, resourceManifest unstructured.Unstructured, gvk schema.GroupVersionKind, rbacCallback func(clusterName string, resourceIdentifier k8s2.ResourceIdentifier) bool) bool {
	validateCallback := func(namespace, group, kind, resourceName string) bool {
		resourceIdentifier := k8s2.ResourceIdentifier{
			Name:      resourceName,
			Namespace: namespace,
			GroupVersionKind: schema.GroupVersionKind{
				Group: group,
				Kind:  kind,
			},
		}
		return rbacCallback(clusterName, resourceIdentifier)
	}
	return impl.K8sUtil.ValidateResource(resourceManifest.Object, gvk, validateCallback)
}

func (impl *K8sApplicationServiceImpl) ValidateClusterResourceBean(ctx context.Context, clusterId int, manifest unstructured.Unstructured, gvk schema.GroupVersionKind, rbacCallback func(clusterName string, resourceIdentifier k8s2.ResourceIdentifier) bool) bool {
	clusterBean, err := impl.clusterReadService.FindById(clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting clusterBean by cluster Id", "clusterId", clusterId, "err", err)
		return false
	}
	return impl.validateResourceManifest(clusterBean.ClusterName, manifest, gvk, rbacCallback)
}

func (impl *K8sApplicationServiceImpl) ValidateResourceRequest(ctx context.Context, appIdentifier *bean.AppIdentifier, request *k8s2.K8sRequestBean) error {
	if valid, err := impl.validateResourceRequest(ctx, appIdentifier, request); err != nil || !valid {
		if !valid {
			impl.logger.Errorw("validation error in resource request", "request.AppIdentifier", appIdentifier, "request.K8sRequest", request)
			err = &util.ApiError{
				HttpStatusCode:  http.StatusBadRequest,
				InternalMessage: "validation failed for the requested resource",
				UserMessage:     fmt.Sprintf("resource %s: \"%s\" doesn't exist", request.ResourceIdentifier.GroupVersionKind.Kind, request.ResourceIdentifier.Name),
			}
		} else if err != nil {
			impl.logger.Errorw("error in validating resource request", "err", err, "request.AppIdentifier", appIdentifier, "request.K8sRequest", request)
		}
		return err
	}
	return nil
}

func (impl *K8sApplicationServiceImpl) validateResourceRequest(ctx context.Context, appIdentifier *bean.AppIdentifier, request *k8s2.K8sRequestBean) (bool, error) {
	app, err := impl.helmAppService.GetApplicationDetail(ctx, appIdentifier)
	if err != nil {
		impl.logger.Errorw("error in getting app detail", "err", err, "appDetails", appIdentifier)
		apiError := clientErrors.ConvertToApiError(err)
		if apiError != nil {
			err = apiError
		}
		return false, err
	}
	valid := false
	for _, node := range app.ResourceTreeResponse.Nodes {
		nodeDetails := k8s2.ResourceIdentifier{
			Name:      node.Name,
			Namespace: node.Namespace,
			GroupVersionKind: schema.GroupVersionKind{
				Group:   node.Group,
				Version: node.Version,
				Kind:    node.Kind,
			},
		}
		if nodeDetails == request.ResourceIdentifier {
			valid = true
			break
		}
	}
	return impl.validateContainerNameIfReqd(valid, request, app), nil
}

func (impl *K8sApplicationServiceImpl) ValidateFluxResourceRequest(ctx context.Context, appIdentifier *bean2.FluxAppIdentifier, request *k8s2.K8sRequestBean) (bool, error) {
	app, err := impl.fluxApplicationService.GetFluxAppDetail(ctx, appIdentifier)
	if err != nil {
		impl.logger.Errorw("error in getting app detail", "err", err, "appDetails", appIdentifier)
		apiError := clientErrors.ConvertToApiError(err)
		if apiError != nil {
			err = apiError
		}
		return false, err
	}

	valid := false
	for _, node := range app.ResourceTreeResponse.Nodes {
		nodeDetails := k8s2.ResourceIdentifier{
			Name:      node.Name,
			Namespace: node.Namespace,
			GroupVersionKind: schema.GroupVersionKind{
				Group:   node.Group,
				Version: node.Version,
				Kind:    node.Kind,
			},
		}
		if nodeDetails == request.ResourceIdentifier {
			valid = true
			break
		}
	}
	appDetail := &gRPC.AppDetail{
		ResourceTreeResponse: app.ResourceTreeResponse,
	}
	return impl.validateContainerNameIfReqd(valid, request, appDetail), nil
}

func (impl *K8sApplicationServiceImpl) validateContainerNameIfReqd(valid bool, request *k8s2.K8sRequestBean, app *gRPC.AppDetail) bool {
	if !valid {
		requestContainerName := request.PodLogsRequest.ContainerName
		podName := request.ResourceIdentifier.Name
		for _, pod := range app.ResourceTreeResponse.PodMetadata {
			if pod.Name == podName {

				// finding the container name in main Containers
				for _, container := range pod.Containers {
					if container == requestContainerName {
						return true
					}
				}

				// finding the container name in init containers
				for _, initContainer := range pod.InitContainers {
					if initContainer == requestContainerName {
						return true
					}
				}

				// finding the container name in ephemeral containers
				for _, ephemeralContainer := range pod.EphemeralContainers {
					if ephemeralContainer.Name == requestContainerName {
						return true
					}
				}

			}
		}
	}
	return valid
}

func (impl *K8sApplicationServiceImpl) GetResourceInfo(ctx context.Context) (*bean3.ResourceInfo, error) {
	pod, err := impl.K8sUtil.GetResourceInfoByLabelSelector(ctx, impl.aCDAuthConfig.ACDConfigMapNamespace, "app=inception")
	if err != nil {
		err = &util.ApiError{Code: "404", HttpStatusCode: 404, UserMessage: "error on getting resource from k8s"}
		impl.logger.Errorw("error on getting resource from k8s, unable to fetch installer pod", "err", err)
		return nil, err
	}
	response := &bean3.ResourceInfo{PodName: pod.Name}
	return response, nil
}

// GetAllApiResourceGVKWithoutAuthorization  This function will the all the available api resource GVK list for specific cluster
func (impl *K8sApplicationServiceImpl) GetAllApiResourceGVKWithoutAuthorization(ctx context.Context, clusterId int) (*k8s2.GetAllApiResourcesResponse, error) {
	impl.logger.Infow("getting all api-resources without auth", "clusterId", clusterId)
	restConfig, err, _ := impl.k8sCommonService.GetRestConfigByClusterId(ctx, clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting cluster rest config", "clusterId", clusterId, "err", err)
		return nil, err
	}
	allApiResources, err := impl.K8sUtil.GetApiResources(restConfig, bean3.LIST_VERB)
	if err != nil {
		if client.IsClusterUnReachableError(err) {
			impl.logger.Errorw("k8s cluster unreachable", "err", err)
			return nil, &util.ApiError{HttpStatusCode: http.StatusBadRequest, UserMessage: err.Error()}
		}
		return nil, err
	}
	// FILTER STARTS
	// 1) remove ""/v1 event kind if event kind exist in events.k8s.io/v1 and ""/v1
	k8sEventIndex := -1
	v1EventIndex := -1
	for index, apiResource := range allApiResources {
		gvk := apiResource.Gvk
		if gvk.Kind == bean3.EVENT_K8S_KIND && gvk.Version == "v1" {
			if gvk.Group == "" {
				v1EventIndex = index
			} else if gvk.Group == "events.k8s.io" {
				k8sEventIndex = index
			}
		}
	}
	if k8sEventIndex > -1 && v1EventIndex > -1 {
		allApiResources = append(allApiResources[:v1EventIndex], allApiResources[v1EventIndex+1:]...)
	}
	// FILTER ENDS

	response := &k8s2.GetAllApiResourcesResponse{
		ApiResources: allApiResources,
	}
	return response, nil
}

func (impl *K8sApplicationServiceImpl) GetAllApiResources(ctx context.Context, clusterId int, isSuperAdmin bool, userId int32) (*k8s2.GetAllApiResourcesResponse, error) {
	impl.logger.Infow("getting all api-resources", "clusterId", clusterId)
	apiResourceGVKResponse, err := impl.GetAllApiResourceGVKWithoutAuthorization(ctx, clusterId)
	if err != nil {
		return nil, err
	}
	allApiResources := apiResourceGVKResponse.ApiResources

	// RBAC FILER STARTS
	allowedAll := isSuperAdmin
	filteredApiResources := make([]*k8s2.K8sApiResource, 0)
	if !isSuperAdmin {
		clusterBean, err := impl.clusterReadService.FindById(clusterId)
		if err != nil {
			impl.logger.Errorw("failed to find cluster for id", "err", err, "clusterId", clusterId)
			return nil, err
		}
		roles, err := impl.clusterService.FetchRolesFromGroup(userId)
		if err != nil {
			impl.logger.Errorw("error on fetching user roles for cluster list", "err", err)
			return nil, err
		}

		allowedGroupKinds := make(map[string]bool) // group||kind
		for _, role := range roles {
			if clusterBean.ClusterName != role.Cluster {
				continue
			}
			kind := role.Kind
			if role.Group == "" && kind == "" {
				allowedAll = true
				break
			}
			groupName := role.Group
			if groupName == "" {
				groupName = "*"
			} else if groupName == casbin.ClusterEmptyGroupPlaceholder {
				groupName = ""
			}
			allowedGroupKinds[groupName+"||"+kind] = true
			// add children for this kind
			children, found := k8sCommonBean.KindVsChildrenGvk[kind]
			if found {
				// if rollout kind other than argo, then neglect only
				if kind != k8sCommonBean.K8sClusterResourceRolloutKind || groupName == k8sCommonBean.K8sClusterResourceRolloutGroup {
					for _, child := range children {
						allowedGroupKinds[child.Group+"||"+child.Kind] = true
					}
				}
			}
		}

		if !allowedAll {
			for _, apiResource := range allApiResources {
				gvk := apiResource.Gvk
				_, found := allowedGroupKinds[gvk.Group+"||"+gvk.Kind]
				if found {
					filteredApiResources = append(filteredApiResources, apiResource)
				} else {
					_, found = allowedGroupKinds["*"+"||"+gvk.Kind]
					if found {
						filteredApiResources = append(filteredApiResources, apiResource)
					}
				}
			}
		}
	}
	response := &k8s2.GetAllApiResourcesResponse{
		AllowedAll: allowedAll,
	}
	if allowedAll {
		response.ApiResources = allApiResources
	} else {
		response.ApiResources = filteredApiResources
	}
	// RBAC FILER ENDS

	return response, nil
}

func (impl *K8sApplicationServiceImpl) GetResourceList(ctx context.Context, token string, request *bean4.ResourceRequestBean, validateResourceAccess func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool) (*k8s2.ClusterResourceListMap, error) {
	resourceList := &k8s2.ClusterResourceListMap{}
	clusterId := request.ClusterId
	restConfig, err, clusterBean := impl.k8sCommonService.GetRestConfigByClusterId(ctx, clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting rest config by cluster Id", "err", err, "clusterId", request.ClusterId)
		return resourceList, err
	}
	return impl.GetResourceListWithRestConfig(ctx, token, request, validateResourceAccess, restConfig, clusterBean.ClusterName)
}

func (impl *K8sApplicationServiceImpl) GetResourceListWithRestConfig(ctx context.Context, token string, request *bean4.ResourceRequestBean,
	validateResourceAccess func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool,
	restConfig *rest.Config, clusterName string) (*k8s2.ClusterResourceListMap, error) {
	resourceList := &k8s2.ClusterResourceListMap{}
	k8sRequest := request.K8sRequest
	// store the copy of requested resource identifier
	resourceIdentifierCloned := k8sRequest.ResourceIdentifier
	resp, namespaced, err := impl.K8sUtil.GetResourceList(ctx, restConfig, resourceIdentifierCloned.GroupVersionKind, resourceIdentifierCloned.Namespace, true, nil)
	if err != nil {
		impl.logger.Errorw("error in getting resource list", "err", err, "request", request)
		return resourceList, err
	}
	checkForResourceCallback := func(namespace, group, kind, resourceName string) bool {
		if validateResourceAccess == nil { // if resource validate rbac func is nil then allow
			return true
		}
		resourceIdentifier := resourceIdentifierCloned
		resourceIdentifier.Name = resourceName
		resourceIdentifier.Namespace = namespace
		if group != "" && kind != "" {
			resourceIdentifier.GroupVersionKind = schema.GroupVersionKind{Group: group, Kind: kind}
		}
		k8sRequest.ResourceIdentifier = resourceIdentifier
		return validateResourceAccess(token, clusterName, *request, casbin.ActionGet)
	}
	resourceList, err = impl.K8sUtil.BuildK8sObjectListTableData(&resp.Resources, namespaced, request.K8sRequest.ResourceIdentifier.GroupVersionKind, false, checkForResourceCallback)
	if err != nil {
		impl.logger.Errorw("error on parsing for k8s resource", "err", err)
		return resourceList, err
	}
	return resourceList, nil
}

func (impl *K8sApplicationServiceImpl) ApplyResources(ctx context.Context, token string, request *k8s2.ApplyResourcesRequest, validateResourceAccess func(token string, clusterName string, request bean4.ResourceRequestBean, casbinAction string) bool) ([]*k8s2.ApplyResourcesResponse, error) {
	manifests, err := yamlUtil.SplitYAMLs([]byte(request.Manifest))
	if err != nil {
		impl.logger.Errorw("error in splitting yaml in manifest", "err", err)
		return nil, err
	}

	// getting rest config by clusterId
	clusterId := request.ClusterId
	restConfig, err, clusterBean := impl.k8sCommonService.GetRestConfigByClusterId(ctx, clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting rest config by cluster", "clusterId", clusterId, "err", err)
		return nil, err
	}

	var response []*k8s2.ApplyResourcesResponse
	for _, manifest := range manifests {
		var namespace string
		manifestNamespace := manifest.GetNamespace()
		if len(manifestNamespace) > 0 {
			namespace = manifestNamespace
		} else {
			namespace = bean3.DEFAULT_NAMESPACE
		}
		manifestRes := &k8s2.ApplyResourcesResponse{
			Name: manifest.GetName(),
			Kind: manifest.GetKind(),
		}
		resourceRequestBean := bean4.ResourceRequestBean{
			ClusterId: clusterId,
			K8sRequest: &k8s2.K8sRequestBean{
				ResourceIdentifier: k8s2.ResourceIdentifier{
					Name:             manifest.GetName(),
					Namespace:        namespace,
					GroupVersionKind: manifest.GroupVersionKind(),
				},
			},
		}
		actionAllowed := validateResourceAccess(token, clusterBean.ClusterName, resourceRequestBean, casbin.ActionUpdate)
		if actionAllowed {
			resourceExists, err := impl.applyResourceFromManifest(ctx, manifest, restConfig, namespace, clusterId)
			manifestRes.IsUpdate = resourceExists
			if err != nil {
				manifestRes.Error = err.Error()
			}
		} else {
			manifestRes.Error = "permission-denied"
		}
		response = append(response, manifestRes)
	}

	return response, nil
}

func (impl *K8sApplicationServiceImpl) applyResourceFromManifest(ctx context.Context, manifest unstructured.Unstructured, restConfig *rest.Config, namespace string, clusterId int) (bool, error) {
	var isUpdateResource bool
	k8sRequestBean := &k8s2.K8sRequestBean{
		ResourceIdentifier: k8s2.ResourceIdentifier{
			Name:             manifest.GetName(),
			Namespace:        namespace,
			GroupVersionKind: manifest.GroupVersionKind(),
		},
	}
	jsonStrByteErr, err := json.Marshal(manifest.UnstructuredContent())
	if err != nil {
		impl.logger.Errorw("error in marshalling json", "err", err)
		return isUpdateResource, err
	}
	jsonStr := string(jsonStrByteErr)
	request := &bean4.ResourceRequestBean{
		K8sRequest: k8sRequestBean,
		ClusterId:  clusterId,
	}

	_, err = impl.k8sCommonService.GetResource(ctx, request)
	if err != nil {
		statusError, ok := err.(*errors2.StatusError)
		if !ok || statusError == nil || statusError.ErrStatus.Reason != metav1.StatusReasonNotFound {
			impl.logger.Errorw("error in getting resource", "err", err)
			return isUpdateResource, err
		}
		resourceIdentifier := k8sRequestBean.ResourceIdentifier
		// case of resource not found
		_, err = impl.K8sUtil.CreateResources(ctx, restConfig, jsonStr, resourceIdentifier.GroupVersionKind, resourceIdentifier.Namespace)
		if err != nil {
			impl.logger.Errorw("error in creating resource", "err", err)
			return isUpdateResource, err
		}
	} else {
		// case of resource update
		isUpdateResource = true
		resourceIdentifier := k8sRequestBean.ResourceIdentifier
		_, err = impl.K8sUtil.PatchResourceRequest(ctx, restConfig, types.StrategicMergePatchType, jsonStr, resourceIdentifier.Name, resourceIdentifier.Namespace, resourceIdentifier.GroupVersionKind)
		if err != nil {
			impl.logger.Errorw("error in updating resource", "err", err)
			return isUpdateResource, err
		}
	}

	return isUpdateResource, nil
}
func (impl *K8sApplicationServiceImpl) CreatePodEphemeralContainers(req *bean5.EphemeralContainerRequest) error {
	var clientSet *kubernetes.Clientset
	var v1Client *v1.CoreV1Client
	var err error
	if req.ExternalArgoAppIdentifier != nil {
		clientSet, v1Client, err = impl.k8sCommonService.GetCoreClientByClusterIdForExternalArgoApps(req)
		if err != nil {
			impl.logger.Errorw("error in getting coreV1 client by clusterId", "err", err, "req", req)
			return err
		}
	} else {
		clientSet, v1Client, err = impl.k8sCommonService.GetCoreClientByClusterId(req.ClusterId)
		if err != nil {
			impl.logger.Errorw("error in getting coreV1 client by clusterId", "clusterId", req.ClusterId, "err", err)
			return err
		}
	}
	compatible, err := impl.K8sServerVersionCheckForEphemeralContainers(clientSet)
	if err != nil {
		impl.logger.Errorw("error in checking kubernetes server version compatability for ephemeral containers", "clusterId", req.ClusterId, "err", err)
		return err
	}
	if !compatible {
		return errors.New("This feature is supported on and above Kubernetes v1.23 only.")
	}
	pod, err := impl.K8sUtil.GetPodByName(req.Namespace, req.PodName, v1Client)
	if err != nil {
		impl.logger.Errorw("error in getting pod", "clusterId", req.ClusterId, "namespace", req.Namespace, "podName", req.PodName, "err", err)
		return err
	}

	podJS, err := json.Marshal(pod)
	if err != nil {
		impl.logger.Errorw("error occurred in unMarshaling pod object", "podObject", pod, "err", err)
		return fmt.Errorf("error creating JSON for pod: %v", err)
	}
	debugPod, debugContainer, err := impl.generateDebugContainer(pod, *req)
	if err != nil {
		impl.logger.Errorw("error in generateDebugContainer", "request", req, "err", err)
		return err
	}

	debugJS, err := json.Marshal(debugPod)
	if err != nil {
		impl.logger.Errorw("error occurred in unMarshaling debugPod object", "debugPod", debugPod, "err", err)
		return fmt.Errorf("error creating JSON for pod: %v", err)
	}

	patch, err := strategicpatch.CreateTwoWayMergePatch(podJS, debugJS, pod)
	if err != nil {
		impl.logger.Errorw("error occurred in CreateTwoWayMergePatch", "podJS", podJS, "debugJS", debugJS, "pod", pod, "err", err)
		return fmt.Errorf("error creating patch to add debug container: %v", err)
	}

	_, err = v1Client.Pods(req.Namespace).Patch(context.Background(), pod.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{}, "ephemeralcontainers")
	if err != nil {
		if serr, ok := err.(*errors2.StatusError); ok && serr.Status().Reason == metav1.StatusReasonNotFound && serr.ErrStatus.Details.Name == "" {
			impl.logger.Errorw("error occurred while creating ephemeral containers", "err", err, "reason", "ephemeral containers are disabled for this cluster")
			return fmt.Errorf("ephemeral containers are disabled for this cluster (error from kubernetes server: %q)", err)
		}
		if runtime.IsNotRegisteredError(err) {
			patch, err := json.Marshal([]map[string]interface{}{{
				"op":    "add",
				"path":  "/ephemeralContainers/-",
				"value": debugContainer,
			}})
			if err != nil {
				impl.logger.Errorw("error occured while trying to create epehemral containers with legacy API", "err", err)
				return fmt.Errorf("error creating JSON 6902 patch for old /ephemeralcontainers API: %s", err)
			}
			// try with legacy API
			result := v1Client.RESTClient().Patch(types.JSONPatchType).
				Namespace(pod.Namespace).
				Resource("pods").
				Name(pod.Name).
				SubResource("ephemeralcontainers").
				Body(patch).
				Do(context.Background())
			return result.Error()
		}
		return err
	}

	if err == nil {
		debugContainerJs, err := json.Marshal(debugContainer)
		if err != nil {
			impl.logger.Errorw("error occurred in unMarshaling debugContainer object", "debugContainerJs", debugContainer, "err", err)
			return fmt.Errorf("error creating JSON for pod: %v", err)
		}
		req.AdvancedData = &bean5.EphemeralContainerAdvancedData{
			Manifest: string(debugContainerJs),
		}
		req.BasicData = &bean5.EphemeralContainerBasicData{
			ContainerName:       debugContainer.Name,
			TargetContainerName: debugContainer.TargetContainerName,
			Image:               debugContainer.Image,
		}
		err = impl.ephemeralContainerService.AuditEphemeralContainerAction(*req, repository.ActionCreate)
		if err != nil {
			impl.logger.Errorw("error in saving ephemeral container data", "err", err)
			return err
		}
		return nil
	}

	impl.logger.Errorw("error in creating ephemeral containers ", "err", err, "clusterId", req.ClusterId, "namespace", req.Namespace, "podName", req.PodName, "ephemeralContainerSpec", debugContainer)
	return err
}

func (impl *K8sApplicationServiceImpl) generateDebugContainer(pod *corev1.Pod, req bean5.EphemeralContainerRequest) (*corev1.Pod, *corev1.EphemeralContainer, error) {
	copied := pod.DeepCopy()
	ephemeralContainer := &corev1.EphemeralContainer{}
	if req.AdvancedData != nil {
		err := json.Unmarshal([]byte(req.AdvancedData.Manifest), ephemeralContainer)
		if err != nil {
			impl.logger.Errorw("error occurred in unMarshaling advanced ephemeral data", "err", err, "advancedData", req.AdvancedData.Manifest)
			return copied, ephemeralContainer, err
		}
		if ephemeralContainer.TargetContainerName == "" || ephemeralContainer.Name == "" || ephemeralContainer.Image == "" {
			return copied, ephemeralContainer, errors.New("containerName,targetContainerName and image cannot be empty")
		}
		if len(ephemeralContainer.Command) > 0 {
			return copied, ephemeralContainer, errors.New("Command field is not supported, please remove command and try again")
		}
	} else {
		ephemeralContainer = &corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:                     req.BasicData.ContainerName,
				Env:                      nil,
				Image:                    req.BasicData.Image,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				Stdin:                    true,
				TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				TTY:                      true,
			},
			TargetContainerName: req.BasicData.TargetContainerName,
		}
	}
	ephemeralContainer.Name = ephemeralContainer.Name + "-" + util2.Generate(5)
	scriptCreateCommand := fmt.Sprintf("echo 'while true; do sleep 600; done;' > "+k8sObjectUtils.EphemeralContainerStartingShellScriptFileName, ephemeralContainer.Name)
	scriptRunCommand := fmt.Sprintf("sh "+k8sObjectUtils.EphemeralContainerStartingShellScriptFileName, ephemeralContainer.Name)
	ephemeralContainer.Command = []string{"sh", "-c", scriptCreateCommand + " && " + scriptRunCommand}
	copied.Spec.EphemeralContainers = append(copied.Spec.EphemeralContainers, *ephemeralContainer)
	ephemeralContainer = &copied.Spec.EphemeralContainers[len(copied.Spec.EphemeralContainers)-1]
	return copied, ephemeralContainer, nil

}

func (impl *K8sApplicationServiceImpl) TerminatePodEphemeralContainer(req bean5.EphemeralContainerRequest) (bool, error) {
	terminalReq := &terminal.TerminalSessionRequest{
		PodName:                     req.PodName,
		ClusterId:                   req.ClusterId,
		Namespace:                   req.Namespace,
		ContainerName:               req.BasicData.ContainerName,
		ExternalArgoApplicationName: req.ExternalArgoApplicationName,
	}
	container, err := impl.ephemeralContainerRepository.FindContainerByName(terminalReq.ClusterId, terminalReq.Namespace, terminalReq.PodName, terminalReq.ContainerName)
	if err != nil {
		impl.logger.Errorw("error in finding ephemeral container in the database", "err", err, "ClusterId", terminalReq.ClusterId, "Namespace", terminalReq.Namespace, "PodName", terminalReq.PodName, "ContainerName", terminalReq.ContainerName)
		return false, err
	}
	if container == nil {
		return false, errors.New("externally created ephemeral containers cannot be removed")
	}
	// Check if pod exists and is running before attempting to execute command
	var v1Client *v1.CoreV1Client
	if req.ExternalArgoAppIdentifier != nil {
		_, v1Client, err = impl.k8sCommonService.GetCoreClientByClusterIdForExternalArgoApps(&req)
		if err != nil {
			impl.logger.Errorw("error in getting coreV1 client by clusterId for external argo apps", "err", err, "req", req)
			return false, err
		}
	} else {
		_, v1Client, err = impl.k8sCommonService.GetCoreClientByClusterId(req.ClusterId)
		if err != nil {
			impl.logger.Errorw("error in getting coreV1 client by clusterId", "clusterId", req.ClusterId, "err", err)
			return false, err
		}
	}

	// Check if pod exists and is running
	pod, err := impl.K8sUtil.GetPodByName(req.Namespace, req.PodName, v1Client)
	if err != nil {
		if k8s.IsResourceNotFoundErr(err) {
			impl.logger.Infow("pod not found, ephemeral container termination not needed", "podName", req.PodName, "namespace", req.Namespace, "clusterId", req.ClusterId)
			// Pod doesn't exist, so ephemeral container is already terminated
			err = impl.ephemeralContainerService.AuditEphemeralContainerAction(req, repository.ActionTerminate)
			if err != nil {
				impl.logger.Errorw("error in saving ephemeral container data", "err", err)
				return true, err
			}
			return true, nil
		}
		impl.logger.Errorw("error in getting pod", "clusterId", req.ClusterId, "namespace", req.Namespace, "podName", req.PodName, "err", err)
		return false, err
	}

	// Check if pod is in a terminated state
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		impl.logger.Infow("pod is in terminated state, ephemeral container termination not needed", "podName", req.PodName, "namespace", req.Namespace, "clusterId", req.ClusterId, "podPhase", pod.Status.Phase)
		// Pod is terminated, so ephemeral container is already terminated
		err = impl.ephemeralContainerService.AuditEphemeralContainerAction(req, repository.ActionTerminate)
		if err != nil {
			impl.logger.Errorw("error in saving ephemeral container data", "err", err)
			return true, err
		}
		return true, nil
	}

	// Check if the specific ephemeral container is still running
	ephemeralContainerRunning := false
	for _, ecStatus := range pod.Status.EphemeralContainerStatuses {
		if ecStatus.Name == req.BasicData.ContainerName && ecStatus.State.Running != nil {
			ephemeralContainerRunning = true
			break
		}
	}

	if !ephemeralContainerRunning {
		impl.logger.Infow("ephemeral container is not running, termination not needed", "podName", req.PodName, "namespace", req.Namespace, "clusterId", req.ClusterId, "containerName", req.BasicData.ContainerName)
		// Ephemeral container is not running, so it's already terminated
		err = impl.ephemeralContainerService.AuditEphemeralContainerAction(req, repository.ActionTerminate)
		if err != nil {
			impl.logger.Errorw("error in saving ephemeral container data", "err", err)
			return true, err
		}
		return true, nil
	}
	containerKillCommand := fmt.Sprintf("kill -16 $(pgrep -f '%s' -o)", fmt.Sprintf(k8sObjectUtils.EphemeralContainerStartingShellScriptFileName, terminalReq.ContainerName))
	cmds := []string{"sh", "-c", containerKillCommand}
	_, errBuf, err := impl.terminalSession.RunCmdInRemotePod(terminalReq, cmds)
	if err != nil {
		impl.logger.Errorw("failed to execute commands ", "err", err, "commands", cmds, "podName", req.PodName, "namespace", req.Namespace)
		// not returning the error since websocket connection will break when running kill command
	}
	errBufString := errBuf.String()
	if errBufString != "" {
		impl.logger.Errorw("error response on executing commands ", "err", errBufString, "commands", cmds, "podName", req.Namespace, "namespace", req.Namespace)
		// not returning the error since websocket connection will break when running kill command
	}

	if err == nil {

		err = impl.ephemeralContainerService.AuditEphemeralContainerAction(req, repository.ActionTerminate)
		if err != nil {
			impl.logger.Errorw("error in saving ephemeral container data", "err", err)
			return true, err
		}

	}

	return true, nil
}

func (impl *K8sApplicationServiceImpl) GetPodContainersList(clusterId int, namespace, podName string) (*bean4.PodContainerList, error) {
	_, v1Client, err := impl.k8sCommonService.GetCoreClientByClusterId(clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting coreV1 client by clusterId", "clusterId", clusterId, "err", err)
		return nil, err
	}
	pod, err := impl.K8sUtil.GetPodByName(namespace, podName, v1Client)
	if err != nil {
		impl.logger.Errorw("error in getting pod", "clusterId", clusterId, "namespace", namespace, "podName", podName, "err", err)
		return nil, err
	}
	ephemeralContainerStatusMap := make(map[string]bool)
	for _, c := range pod.Status.EphemeralContainerStatuses {
		// c.state contains three states running,waiting and terminated
		// at any point of time only one state will be there
		if c.State.Running != nil {
			ephemeralContainerStatusMap[c.Name] = true
		}
	}
	containers := make([]string, len(pod.Spec.Containers))
	initContainers := make([]string, len(pod.Spec.InitContainers))
	ephemeralContainers := make([]string, 0, len(pod.Spec.EphemeralContainers))

	for i, c := range pod.Spec.Containers {
		containers[i] = c.Name
	}

	for _, ec := range pod.Spec.EphemeralContainers {
		if _, ok := ephemeralContainerStatusMap[ec.Name]; ok {
			ephemeralContainers = append(ephemeralContainers, ec.Name)
		}
	}

	for i, ic := range pod.Spec.InitContainers {
		initContainers[i] = ic.Name
	}

	return &bean4.PodContainerList{
		Containers:          containers,
		EphemeralContainers: ephemeralContainers,
		InitContainers:      initContainers,
	}, nil
}

func (impl *K8sApplicationServiceImpl) GetPodListByLabel(clusterId int, namespace, label string) ([]corev1.Pod, error) {
	clientSet, _, err := impl.k8sCommonService.GetCoreClientByClusterId(clusterId)
	if err != nil {
		impl.logger.Errorw("error in getting coreV1 client by clusterId", "clusterId", clusterId, "err", err)
		return nil, err
	}
	pods, err := impl.K8sUtil.GetPodListByLabel(namespace, label, clientSet)
	if err != nil {
		impl.logger.Errorw("error in getting pods list", "clusterId", clusterId, "namespace", namespace, "label", label, "err", err)
		return nil, err
	}
	return pods, err
}

func (impl *K8sApplicationServiceImpl) RecreateResource(ctx context.Context, request *bean4.ResourceRequestBean) (*k8s2.ManifestResponse, error) {
	resourceIdentifier := &openapi.ResourceIdentifier{
		Name:      &request.K8sRequest.ResourceIdentifier.Name,
		Namespace: &request.K8sRequest.ResourceIdentifier.Namespace,
		Group:     &request.K8sRequest.ResourceIdentifier.GroupVersionKind.Group,
		Version:   &request.K8sRequest.ResourceIdentifier.GroupVersionKind.Version,
		Kind:      &request.K8sRequest.ResourceIdentifier.GroupVersionKind.Kind,
	}
	manifestRes, err := impl.helmAppService.GetDesiredManifest(ctx, request.AppIdentifier, resourceIdentifier)
	if err != nil {
		impl.logger.Errorw("error in getting desired manifest for validation", "err", err)
		apiError := clientErrors.ConvertToApiError(err)
		if apiError != nil {
			err = apiError
		}
		return nil, err
	}
	manifest, manifestOk := manifestRes.GetManifestOk()
	if manifestOk == false || len(*manifest) == 0 {
		impl.logger.Debugw("invalid request, desired manifest not found", "err", err)
		return nil, fmt.Errorf("no manifest found for this request")
	}

	// getting rest config by clusterId
	restConfig, err, _ := impl.k8sCommonService.GetRestConfigByClusterId(ctx, request.AppIdentifier.ClusterId)
	if err != nil {
		impl.logger.Errorw("error in getting rest config by cluster Id", "err", err, "clusterId", request.AppIdentifier.ClusterId)
		return nil, err
	}
	resp, err := impl.K8sUtil.CreateResources(ctx, restConfig, *manifest, request.K8sRequest.ResourceIdentifier.GroupVersionKind, request.K8sRequest.ResourceIdentifier.Namespace)
	if err != nil {
		impl.logger.Errorw("error in creating resource", "err", err, "request", request)
		return nil, err
	}
	return resp, nil
}

func (impl *K8sApplicationServiceImpl) DeleteResourceWithAudit(ctx context.Context, request *bean4.ResourceRequestBean, userId int32) (*k8s2.ManifestResponse, error) {
	resp, err := impl.k8sCommonService.DeleteResource(ctx, request)
	if err != nil {
		if k8s.IsResourceNotFoundErr(err) {
			return nil, &utils.ApiError{Code: "404",
				HttpStatusCode:  http.StatusNotFound,
				InternalMessage: err.Error(),
				UserMessage:     bean4.ResourceNotFoundErr}
		}
		impl.logger.Errorw("error in deleting resource", "err", err)
		return nil, err
	}
	if request.AppIdentifier != nil {
		saveAuditLogsErr := impl.K8sResourceHistoryService.SaveHelmAppsResourceHistory(request.AppIdentifier, request.K8sRequest, userId, bean3.Delete)
		if saveAuditLogsErr != nil {
			impl.logger.Errorw("error in saving audit logs for delete resource request", "err", err)
		}
	}

	return resp, nil
}

func (impl *K8sApplicationServiceImpl) GetUrlsByBatchForIngress(ctx context.Context, resp []bean4.BatchResourceResponse) []interface{} {
	result := make([]interface{}, 0)
	for _, res := range resp {
		err := res.Err
		if err != nil {
			continue
		}
		urlRes := getUrls(res.ManifestResponse)
		result = append(result, urlRes)
	}
	return result
}

func getUrls(manifest *k8s2.ManifestResponse) bean3.Response {
	var res bean3.Response
	kind := manifest.Manifest.Object["kind"]
	if _, ok := manifest.Manifest.Object["metadata"]; ok {
		metadata := manifest.Manifest.Object["metadata"].(map[string]interface{})
		if metadata != nil {
			name := metadata["name"]
			if name != nil {
				res.Name = name.(string)
			}
		}
	}

	if kind != nil {
		res.Kind = kind.(string)
	}
	res.PointsTo = ""
	urls := make([]string, 0)
	if res.Kind == k8sCommonBean.IngressKind {
		if manifest.Manifest.Object["spec"] != nil {
			spec := manifest.Manifest.Object["spec"].(map[string]interface{})
			if spec["rules"] != nil {
				rules := spec["rules"].([]interface{})
				for _, rule := range rules {
					ruleMap := rule.(map[string]interface{})
					url := ""
					if ruleMap["host"] != nil {
						url = ruleMap["host"].(string)
					}
					var httpPaths []interface{}
					if ruleMap["http"] != nil && ruleMap["http"].(map[string]interface{})["paths"] != nil {
						httpPaths = ruleMap["http"].(map[string]interface{})["paths"].([]interface{})
					} else {
						continue
					}
					for _, httpPath := range httpPaths {
						path := httpPath.(map[string]interface{})["path"]
						if path != nil {
							url = url + path.(string)
						}
						urls = append(urls, url)
					}
				}
			}
		}
	}

	if manifest.Manifest.Object["status"] != nil {
		status := manifest.Manifest.Object["status"].(map[string]interface{})
		if status["loadBalancer"] != nil {
			loadBalancer := status["loadBalancer"].(map[string]interface{})
			if loadBalancer["ingress"] != nil {
				ingressArray := loadBalancer["ingress"].([]interface{})
				if len(ingressArray) > 0 {
					if hostname, ok := ingressArray[0].(map[string]interface{})["hostname"]; ok {
						res.PointsTo = hostname.(string)
					} else if ip, ok := ingressArray[0].(map[string]interface{})["ip"]; ok {
						res.PointsTo = ip.(string)
					}
				}
			}
		}
	}
	res.Urls = urls
	return res
}

func (impl K8sApplicationServiceImpl) K8sServerVersionCheckForEphemeralContainers(clientSet *kubernetes.Clientset) (bool, error) {
	k8sServerVersion, err := impl.K8sUtil.GetK8sServerVersion(clientSet)
	if err != nil || k8sServerVersion == nil {
		impl.logger.Errorw("error occurred in getting k8sServerVersion", "err", err)
		return false, err
	}

	// ephemeral containers feature is introduced in version v1.23 of kubernetes, it is stable from version v1.25
	// https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/
	ephemeralRegex := impl.ephemeralContainerConfig.EphemeralServerVersionRegex
	matched, err := util2.MatchRegexExpression(ephemeralRegex, k8sServerVersion.String())
	if err != nil {
		impl.logger.Errorw("error in matching ephemeral containers support version regex with k8sServerVersion", "err", err, "EphemeralServerVersionRegex", ephemeralRegex)
		return false, err
	}
	return matched, nil
}
