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

package k8s

import (
	"context"
	"encoding/json"
	error2 "errors"
	"fmt"
	"github.com/devtron-labs/common-lib/utils"
	http2 "github.com/devtron-labs/common-lib/utils/http"
	"github.com/devtron-labs/common-lib/utils/k8s/commonBean"
	"github.com/devtron-labs/common-lib/utils/k8s/configMap"
	"io"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/metrics/pkg/apis/metrics/v1beta1"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
	"k8s.io/utils/pointer"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"

	batchV1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	v12 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

func (impl *K8sServiceImpl) getOpts(opts []K8sServiceOpts) Options {
	customOpts := impl.opts
	for _, opt := range opts {
		customOpts = opt(customOpts)
	}
	return customOpts
}

func (impl *K8sServiceImpl) GetCoreV1Client(clusterConfig *ClusterConfig, opts ...K8sServiceOpts) (*v12.CoreV1Client, error) {
	cfg, err := impl.GetRestConfigByCluster(clusterConfig, opts...)
	if err != nil {
		impl.logger.Errorw("error in getting rest config for default cluster", "err", err)
		return nil, err
	}
	return impl.GetCoreV1ClientByRestConfig(cfg)
}

func (impl *K8sServiceImpl) GetClientForInCluster(opts ...K8sServiceOpts) (*v12.CoreV1Client, error) {
	// creates the in-cluster config
	config, err := impl.GetK8sInClusterRestConfig(opts...)
	if err != nil {
		impl.logger.Errorw("error in getting config", "err", err)
		return nil, err
	}

	// creates the clientset
	httpClient, err := OverrideK8sHttpClientWithTracer(config)
	if err != nil {
		impl.logger.Errorw("error in getting http client for default cluster", "err", err)
		return nil, err
	}
	clientset, err := v12.NewForConfigAndClient(config, httpClient)
	if err != nil {
		impl.logger.Errorw("error", "error", err)
		return nil, err
	}
	return clientset, err
}

func (impl *K8sServiceImpl) GetK8sDiscoveryClient(clusterConfig *ClusterConfig, opts ...K8sServiceOpts) (*discovery.DiscoveryClient, error) {
	cfg, err := impl.GetRestConfigByCluster(clusterConfig, opts...)
	if err != nil {
		impl.logger.Errorw("error in getting rest config for default cluster", "err", err)
		return nil, err
	}

	httpClient, err := OverrideK8sHttpClientWithTracer(cfg)
	if err != nil {
		impl.logger.Errorw("error in getting http client for default cluster", "err", err)
		return nil, err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(cfg, httpClient)
	if err != nil {
		impl.logger.Errorw("error", "error", err, "clusterConfig", clusterConfig)
		return nil, err
	}
	return discoveryClient, err
}

func (impl *K8sServiceImpl) GetK8sDiscoveryClientInCluster(opts ...K8sServiceOpts) (*discovery.DiscoveryClient, error) {
	config, err := impl.GetK8sInClusterRestConfig(opts...)
	if err != nil {
		impl.logger.Errorw("error in getting config", "err", err)
		return nil, err
	}

	httpClient, err := OverrideK8sHttpClientWithTracer(config)
	if err != nil {
		impl.logger.Errorw("error in getting http client for default cluster", "err", err)
		return nil, err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(config, httpClient)
	if err != nil {
		impl.logger.Errorw("error", "error", err)
		return nil, err
	}
	return discoveryClient, err
}

func (impl *K8sServiceImpl) CreateNsIfNotExists(namespace string, clusterConfig *ClusterConfig) (ns *v1.Namespace, nsCreated bool, err error) {
	v12Client, err := impl.GetCoreV1Client(clusterConfig)
	if err != nil {
		impl.logger.Errorw("error", "error", err, "clusterConfig", clusterConfig)
		return nil, false, err
	}
	ns, exists, err := impl.GetNsIfExists(namespace, v12Client)
	if err != nil {
		impl.logger.Errorw("error", "error", err)
		return ns, false, err
	}
	if exists {
		nsCreated = false
		impl.logger.Infow("namespace already exist", "namespace", namespace)
		return ns, nsCreated, nil
	}
	impl.logger.Infow("ns not exists creating", "ns", namespace)
	ns, err = impl.CreateNs(namespace, v12Client)
	if err != nil {
		impl.logger.Errorw("error in creating ns", "namespace", namespace, "err", err)
		return nil, false, err
	}
	nsCreated = true
	return ns, nsCreated, err
}

func (impl *K8sServiceImpl) UpdateNSLabels(namespace *v1.Namespace, labels map[string]string, clusterConfig *ClusterConfig) (ns *v1.Namespace, err error) {
	v12Client, err := impl.GetCoreV1Client(clusterConfig)
	if err != nil {
		impl.logger.Errorw("error", "error", err, "clusterConfig", clusterConfig)
		return nil, err
	}
	namespace.Labels = labels
	ns, err = v12Client.Namespaces().Update(context.Background(), namespace, metav1.UpdateOptions{})
	if err != nil {
		impl.logger.Errorw("error in updating ns", "namespace", namespace, "err", err)
		return nil, err
	}
	return ns, nil
}

func (impl *K8sServiceImpl) GetNsIfExists(namespace string, client *v12.CoreV1Client) (ns *v1.Namespace, exists bool, err error) {
	ns, err = client.Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	//ns, err := impl.k8sClient.CoreV1().Namespaces().Get(namespace, metav1.GetOptions{})
	impl.logger.Debugw("ns fetch", "name", namespace, "res", ns)
	if errors.IsNotFound(err) {
		impl.logger.Debugw("namespace not found", "name", namespace, "err", err)
		return nil, false, nil
	} else if err != nil {
		impl.logger.Errorw("error in checking if ns exist", "err", err)
		return nil, false, err
	} else {
		return ns, true, nil
	}

}

func (impl *K8sServiceImpl) CreateNs(namespace string, client *v12.CoreV1Client) (ns *v1.Namespace, err error) {
	nsSpec := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	ns, err = client.Namespaces().Create(context.Background(), nsSpec, metav1.CreateOptions{})
	if err != nil {
		impl.logger.Errorw("error in creating ns", "err", err)
		return nil, err
	} else {
		return ns, nil
	}
}

func (impl *K8sServiceImpl) CreateNsWithLabels(namespace string, labels map[string]string, client *v12.CoreV1Client) (ns *v1.Namespace, err error) {
	nsSpec := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: labels}}
	ns, err = client.Namespaces().Create(context.Background(), nsSpec, metav1.CreateOptions{})
	if err != nil {
		impl.logger.Errorw("error in creating ns", "err", err)
		return nil, err
	} else {
		return ns, nil
	}
}

func (impl *K8sServiceImpl) GetConfigMap(namespace string, name string, client *v12.CoreV1Client) (*v1.ConfigMap, error) {
	return impl.GetConfigMapWithCtx(context.Background(), namespace, name, client)
}

func (impl *K8sServiceImpl) GetConfigMapWithCtx(ctx context.Context, namespace string, name string, client *v12.CoreV1Client) (*v1.ConfigMap, error) {
	cm, err := client.ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting config map", "err", err)
		return nil, err
	} else {
		return cm, nil
	}
}

func (impl *K8sServiceImpl) CreateConfigMap(namespace string, cm *v1.ConfigMap, client *v12.CoreV1Client) (*v1.ConfigMap, error) {
	cm, err := client.ConfigMaps(namespace).Create(context.Background(), cm, metav1.CreateOptions{})
	if err != nil {
		impl.logger.Errorw("error in creating config map", "err", err)
		return nil, err
	} else {
		return cm, nil
	}
}

func (impl *K8sServiceImpl) CreateConfigMapObject(name, namespace string, client *v12.CoreV1Client, opts ...configMap.ConfigMapOption) (*v1.ConfigMap, error) {
	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	for _, option := range opts {
		option(configMap)
	}
	return impl.CreateConfigMap(namespace, configMap, client)
}

func (impl *K8sServiceImpl) DeleteConfigMap(namespace string, name string, client *v12.CoreV1Client) error {
	err := client.ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		impl.logger.Errorw("error in deleting cm", "namespace", namespace, "err", err)
		return err
	}
	return nil
}

func (impl *K8sServiceImpl) UpdateConfigMap(namespace string, cm *v1.ConfigMap, client *v12.CoreV1Client) (*v1.ConfigMap, error) {
	cm, err := client.ConfigMaps(namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
	if err != nil {
		impl.logger.Errorw("error in updating config map", "err", err)
		return nil, err
	} else {
		return cm, nil
	}
}

func (impl *K8sServiceImpl) PatchConfigMap(namespace string, clusterConfig *ClusterConfig, name string, data map[string]interface{}) (*v1.ConfigMap, error) {
	k8sClient, err := impl.GetCoreV1Client(clusterConfig)
	if err != nil {
		impl.logger.Errorw("error in getting k8s client", "err", err)
		return nil, err
	}
	b, err := json.Marshal(data)
	if err != nil {
		impl.logger.Errorw("error in marshalling data", "err", err)
		// TODO: why panic
		panic(err)
	}
	cm, err := k8sClient.ConfigMaps(namespace).Patch(context.Background(), name, types.PatchType(types.MergePatchType), b, metav1.PatchOptions{})
	if err != nil {
		impl.logger.Errorw("error in patching config map", "err", err)
		return nil, err
	} else {
		return cm, nil
	}
	return cm, nil
}

func (impl *K8sServiceImpl) PatchConfigMapJsonType(namespace string, clusterConfig *ClusterConfig, name string, data interface{}, path string) (*v1.ConfigMap, error) {
	v12Client, err := impl.GetCoreV1Client(clusterConfig)
	if err != nil {
		impl.logger.Errorw("error in getting v12 client ", "err", err, "namespace", namespace, "name", name)
		return nil, err
	}
	var patches []*JsonPatchType
	patch := &JsonPatchType{
		Op:    "replace",
		Path:  path,
		Value: data,
	}
	patches = append(patches, patch)
	b, err := json.Marshal(patches)
	if err != nil {
		impl.logger.Errorw("error in getting marshalling pacthes", "err", err, "namespace", namespace)
		// TODO: why panic
		panic(err)
	}

	cm, err := v12Client.ConfigMaps(namespace).Patch(context.Background(), name, types.PatchType(types.JSONPatchType), b, metav1.PatchOptions{})
	if err != nil {
		impl.logger.Errorw("error in patching config map", "err", err, "namespace", namespace)
		return nil, err
	} else {
		return cm, nil
	}
	return cm, nil
}

func (impl *K8sServiceImpl) GetSecret(namespace string, name string, client *v12.CoreV1Client) (*v1.Secret, error) {
	return impl.GetSecretWithCtx(context.Background(), namespace, name, client)
}

func (impl *K8sServiceImpl) GetSecretWithCtx(ctx context.Context, namespace string, name string, client *v12.CoreV1Client) (*v1.Secret, error) {
	secret, err := client.Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting secrets", "err", err, "namespace", namespace)
		return nil, err
	} else {
		return secret, nil
	}
}

func (impl *K8sServiceImpl) CreateSecret(namespace string, data map[string][]byte, secretName string, secretType v1.SecretType, client *v12.CoreV1Client, labels map[string]string, stringData map[string]string) (*v1.Secret, error) {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
	}
	if labels != nil && len(labels) > 0 {
		secret.ObjectMeta.Labels = labels
	}
	if stringData != nil && len(stringData) > 0 {
		secret.StringData = stringData
	}
	if data != nil && len(data) > 0 {
		secret.Data = data
	}
	if len(secretType) > 0 {
		secret.Type = secretType
	}
	return impl.CreateSecretData(namespace, secret, client)
}

func (impl *K8sServiceImpl) CreateSecretData(namespace string, secret *v1.Secret, v1Client *v12.CoreV1Client) (*v1.Secret, error) {
	secret, err := v1Client.Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	return secret, err
}

func (impl *K8sServiceImpl) UpdateSecret(namespace string, secret *v1.Secret, client *v12.CoreV1Client) (*v1.Secret, error) {
	secret, err := client.Secrets(namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		impl.logger.Errorw("error in updating secrets", "err", err, "namespace", namespace)
		return nil, err
	} else {
		return secret, nil
	}
}

func (impl *K8sServiceImpl) DeleteSecret(namespace string, name string, client *v12.CoreV1Client) error {
	err := client.Secrets(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		impl.logger.Errorw("error in deleting secrets", "err", err, "namespace", namespace)
		return err
	}
	return nil
}

func (impl *K8sServiceImpl) DeleteJob(namespace string, name string, clusterConfig *ClusterConfig, opts ...K8sServiceOpts) error {
	_, _, clientSet, err := impl.GetK8sConfigAndClients(clusterConfig, opts...)
	if err != nil {
		impl.logger.Errorw("clientSet err, DeleteJob", "err", err)
		return err
	}
	jobs := clientSet.BatchV1().Jobs(namespace)

	job, err := jobs.Get(context.Background(), name, metav1.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		impl.logger.Errorw("get job err, DeleteJob", "err", err)
		return nil
	}

	if job != nil {
		err := jobs.Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			impl.logger.Errorw("delete err, DeleteJob", "err", err)
			return err
		}
	}

	return nil
}

func (impl *K8sServiceImpl) GetK8sDynamicClient(restConfig *rest.Config, k8sHttpClient *http.Client) (dynamic.Interface, error) {
	dynamicClientSet, err := dynamic.NewForConfigAndClient(restConfig, k8sHttpClient)
	if err != nil {
		impl.logger.Errorw("error in getting client set by rest config for in cluster", "err", err)
		return nil, err
	}
	return dynamicClientSet, nil
}

func (impl *K8sServiceImpl) DiscoveryClientGetLiveZCall(cluster *ClusterConfig, opts ...K8sServiceOpts) ([]byte, error) {
	_, _, k8sClientSet, err := impl.GetK8sConfigAndClients(cluster, opts...)
	if err != nil {
		impl.logger.Errorw("errir in getting clients and configs", "err", err, "clusterName", cluster.ClusterName)
		return nil, err
	}
	//using livez path as healthz path is deprecated
	response, err := impl.GetLiveZCall(commonBean.LiveZ, k8sClientSet)
	if err != nil {
		impl.logger.Errorw("error in getting livez call", "err", err, "clusterName", cluster.ClusterName)
		return nil, err
	}
	return response, err

}

func (impl *K8sServiceImpl) GetLiveZCall(path string, k8sClientSet *kubernetes.Clientset) ([]byte, error) {
	response, err := k8sClientSet.Discovery().RESTClient().Get().AbsPath(path).DoRaw(context.Background())
	if err != nil {
		impl.logger.Errorw("error in getting response from discovery client", "err", err)
		return nil, err
	}
	return response, err
}

func (impl *K8sServiceImpl) CreateJob(namespace string, name string, clusterConfig *ClusterConfig, job *batchV1.Job, opts ...K8sServiceOpts) error {
	_, _, clientSet, err := impl.GetK8sConfigAndClients(clusterConfig, opts...)
	if err != nil {
		impl.logger.Errorw("clientSet err, CreateJob", "err", err)
	}
	time.Sleep(5 * time.Second)

	jobs := clientSet.BatchV1().Jobs(namespace)
	_, err = jobs.Get(context.Background(), name, metav1.GetOptions{})
	if err == nil {
		impl.logger.Errorw("get job err, CreateJob", "err", err)
		time.Sleep(5 * time.Second)
		_, err = jobs.Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			return error2.New("job deletion takes more time than expected, please try after sometime")
		}
	}

	_, err = jobs.Create(context.Background(), job, metav1.CreateOptions{})
	if err != nil {
		impl.logger.Errorw("create err, CreateJob", "err", err)
		return err
	}
	return nil
}

// DeletePod delete pods with label job-name

func (impl *K8sServiceImpl) DeletePodByLabel(namespace string, labels string, clusterConfig *ClusterConfig, opts ...K8sServiceOpts) error {
	_, _, clientSet, err := impl.GetK8sConfigAndClients(clusterConfig, opts...)
	if err != nil {
		impl.logger.Errorw("clientSet err, DeletePod", "err", err)
		return err
	}

	time.Sleep(2 * time.Second)

	pods := clientSet.CoreV1().Pods(namespace)
	podList, err := pods.List(context.Background(), metav1.ListOptions{LabelSelector: labels})
	if err != nil && errors.IsNotFound(err) {
		impl.logger.Errorw("get pod err, DeletePod", "err", err)
		return nil
	}

	for _, pod := range (*podList).Items {
		if pod.Status.Phase != commonBean.Running {
			podName := pod.ObjectMeta.Name
			err := pods.Delete(context.Background(), podName, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				impl.logger.Errorw("delete err, DeletePod", "err", err)
				return err
			}
		}
	}
	return nil
}

// DeleteAndCreateJob Deletes and recreates if job exists else creates the job
func (impl *K8sServiceImpl) DeleteAndCreateJob(content []byte, namespace string, clusterConfig *ClusterConfig) error {
	// Job object from content
	var job batchV1.Job
	err := yaml.Unmarshal(content, &job)
	if err != nil {
		impl.logger.Errorw("Unmarshal err, CreateJobSafely", "err", err)
		return err
	}

	// delete job if exists
	err = impl.DeleteJob(namespace, job.Name, clusterConfig)
	if err != nil {
		impl.logger.Errorw("DeleteJobIfExists err, CreateJobSafely", "err", err)
		return err
	}

	labels := "job-name=" + job.Name
	err = impl.DeletePodByLabel(namespace, labels, clusterConfig)
	if err != nil {
		impl.logger.Errorw("DeleteJobIfExists err, CreateJobSafely", "err", err)
		return err
	}
	// create job
	err = impl.CreateJob(namespace, job.Name, clusterConfig, &job)
	if err != nil {
		impl.logger.Errorw("CreateJob err, CreateJobSafely", "err", err)
		return err
	}

	return nil
}

func (impl *K8sServiceImpl) ListNamespaces(client *v12.CoreV1Client) (*v1.NamespaceList, error) {
	nsList, err := client.Namespaces().List(context.Background(), metav1.ListOptions{})
	if errors.IsNotFound(err) {
		return nsList, nil
	} else if err != nil {
		return nsList, err
	} else {
		return nsList, nil
	}
}

func (impl *K8sServiceImpl) GetClientByToken(serverUrl string, token map[string]string) (*v12.CoreV1Client, error) {
	bearerToken := token[commonBean.BearerToken]
	clusterCfg := &ClusterConfig{Host: serverUrl, BearerToken: bearerToken}
	v12Client, err := impl.GetCoreV1Client(clusterCfg)
	if err != nil {
		impl.logger.Errorw("error in k8s client", "error", err)
		return nil, err
	}
	return v12Client, nil
}

func (impl *K8sServiceImpl) GetResourceInfoByLabelSelector(ctx context.Context, namespace string, labelSelector string) (*v1.Pod, error) {
	inClusterClient, err := impl.GetClientForInCluster()
	if err != nil {
		impl.logger.Errorw("cluster config error", "err", err)
		return nil, err
	}
	pods, err := inClusterClient.Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, err
	} else if len(pods.Items) > 1 {
		err = &utils.ApiError{Code: "406", HttpStatusCode: 200, UserMessage: "found more than one pod for label selector"}
		return nil, err
	} else if len(pods.Items) == 0 {
		err = &utils.ApiError{Code: "404", HttpStatusCode: 200, UserMessage: "no pod found for label selector"}
		return nil, err
	} else {
		return &pods.Items[0], nil
	}
}

func (impl *K8sServiceImpl) GetPodByName(namespace string, name string, client *v12.CoreV1Client) (*v1.Pod, error) {
	pod, err := client.Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("error in fetch pod name", "err", err)
		return nil, err
	} else {
		return pod, nil
	}
}

func (impl *K8sServiceImpl) BuildK8sObjectListTableData(manifest *unstructured.UnstructuredList, namespaced bool, gvk schema.GroupVersionKind, includeMetadata bool, validateResourceAccess func(namespace string, group string, kind string, resourceName string) bool) (*ClusterResourceListMap, error) {
	clusterResourceListMap := &ClusterResourceListMap{}
	// build headers
	var headers []string
	columnIndexes := make(map[int]string)
	kind := gvk.Kind
	if kind == "Event" {
		headers, columnIndexes = impl.getEventKindHeader()
	} else {
		columnDefinitionsUncast := manifest.Object[commonBean.K8sClusterResourceColumnDefinitionKey]
		if columnDefinitionsUncast != nil {
			columnDefinitions := columnDefinitionsUncast.([]interface{})
			for index, cd := range columnDefinitions {
				if cd == nil {
					continue
				}
				columnMap := cd.(map[string]interface{})
				columnNameUncast := columnMap[commonBean.K8sClusterResourceNameKey]
				if columnNameUncast == nil {
					continue
				}
				priorityUncast := columnMap[commonBean.K8sClusterResourcePriorityKey]
				if priorityUncast == nil {
					continue
				}
				columnName := columnNameUncast.(string)
				columnName = strings.ToLower(columnName)
				priority := priorityUncast.(int64)
				if namespaced && index == 1 {
					headers = append(headers, commonBean.K8sClusterResourceNamespaceKey)
				}
				if priority == 0 || (manifest.GetKind() == "Event" && columnName == "source") || (kind == "Pod") {
					columnIndexes[index] = columnName
					headers = append(headers, columnName)
				}
			}
		}
	}

	// build rows
	rowsMapping := make([]map[string]interface{}, 0)
	rowsDataUncast := manifest.Object[commonBean.K8sClusterResourceRowsKey]
	var namespace string
	var allowed bool
	if rowsDataUncast != nil {
		rows := rowsDataUncast.([]interface{})
		for _, row := range rows {
			namespace = ""
			allowed = true
			rowIndex := make(map[string]interface{})
			rowMap := row.(map[string]interface{})
			cellsUncast := rowMap[commonBean.K8sClusterResourceCellKey]
			if cellsUncast == nil {
				continue
			}
			rowCells := cellsUncast.([]interface{})
			for index, columnName := range columnIndexes {
				cellValUncast := rowCells[index]
				var cell interface{}
				if cellValUncast == nil {
					cell = ""
				} else {
					cell = cellValUncast.(interface{})
				}
				rowIndex[columnName] = cell
			}

			cellObjUncast := rowMap[commonBean.K8sClusterResourceObjectKey]
			var cellObj map[string]interface{}
			if cellObjUncast != nil {
				cellObj = cellObjUncast.(map[string]interface{})
				if cellObj != nil {
					rowIndex[commonBean.K8sClusterResourceKindKey] = cellObj[commonBean.K8sClusterResourceKindKey].(string)
					rowIndex[commonBean.K8sClusterResourceApiVersionKey] = cellObj[commonBean.K8sClusterResourceApiVersionKey].(string)

					if cellObj[commonBean.K8sClusterResourceMetadataKey] != nil {
						metadata := cellObj[commonBean.K8sClusterResourceMetadataKey].(map[string]interface{})
						if metadata[commonBean.K8sClusterResourceNamespaceKey] != nil {
							namespace = metadata[commonBean.K8sClusterResourceNamespaceKey].(string)
							if namespaced {
								rowIndex[commonBean.K8sClusterResourceNamespaceKey] = namespace
							}
						}
						if includeMetadata {
							rowIndex[commonBean.K8sClusterResourceMetadataKey] = metadata
						}
					}

					if cellObj[commonBean.K8sClusterResourceSpecKey] != nil {
						spec, ok := cellObj[commonBean.K8sClusterResourceSpecKey].(map[string]interface{})
						if ok {
							rowIndex[commonBean.K8sClusterResourceSpecKey] = spec
						} else {
							impl.logger.Warnw("Not able to cast spec key of manifest to map")
						}
					}
				}
			}
			allowed = impl.ValidateResource(cellObj, gvk, validateResourceAccess)
			if allowed {
				rowsMapping = append(rowsMapping, rowIndex)
			}
		}
	}

	clusterResourceListMap.Headers = headers
	clusterResourceListMap.Data = rowsMapping
	impl.logger.Debugw("resource listing response", "clusterResourceListMap", clusterResourceListMap)
	return clusterResourceListMap, nil
}

func (impl *K8sServiceImpl) ValidateResource(resourceObj map[string]interface{}, gvk schema.GroupVersionKind, validateCallback func(namespace string, group string, kind string, resourceName string) bool) bool {
	resKind := gvk.Kind
	groupName := gvk.Group
	metadata := resourceObj[commonBean.K8sClusterResourceMetadataKey]
	if metadata == nil {
		return false
	}
	metadataMap := metadata.(map[string]interface{})
	var namespace, resourceName string
	var ownerReferences []interface{}
	if metadataMap[commonBean.K8sClusterResourceNamespaceKey] != nil {
		namespace = metadataMap[commonBean.K8sClusterResourceNamespaceKey].(string)
	}
	if metadataMap[commonBean.K8sClusterResourceMetadataNameKey] != nil {
		resourceName = metadataMap[commonBean.K8sClusterResourceMetadataNameKey].(string)
	}
	if metadataMap[commonBean.K8sClusterResourceOwnerReferenceKey] != nil {
		ownerReferences = metadataMap[commonBean.K8sClusterResourceOwnerReferenceKey].([]interface{})
	}
	if len(ownerReferences) > 0 {
		for _, ownerRef := range ownerReferences {
			allowed := impl.ValidateForResource(namespace, ownerRef, validateCallback)
			if allowed {
				return allowed
			}
		}
	}
	// check current RBAC in case not matched with above one
	return validateCallback(namespace, groupName, resKind, resourceName)
}

func (impl *K8sServiceImpl) ValidateForResource(namespace string, resourceRef interface{}, validateCallback func(namespace string, group string, kind string, resourceName string) bool) bool {
	resourceReference := resourceRef.(map[string]interface{})
	resKind := resourceReference[commonBean.K8sClusterResourceKindKey].(string)
	apiVersion := resourceReference[commonBean.K8sClusterResourceApiVersionKey].(string)
	groupName := ""
	if strings.Contains(apiVersion, "/") {
		groupName = apiVersion[:strings.LastIndex(apiVersion, "/")] // extracting group from this apiVersion
	}
	resName := ""
	if resourceReference["name"] != "" {
		resName = resourceReference["name"].(string)
		switch resKind {
		case commonBean.ReplicaSetKind:
			// check deployment first, then RO and then RS
			if strings.Contains(resName, "-") {
				deploymentName := resName[:strings.LastIndex(resName, "-")]
				allowed := validateCallback(namespace, groupName, commonBean.DeploymentKind, deploymentName)
				if allowed {
					return true
				}
				allowed = validateCallback(namespace, commonBean.K8sClusterResourceRolloutGroup, commonBean.K8sClusterResourceRolloutKind, deploymentName)
				if allowed {
					return true
				}
			}
			allowed := validateCallback(namespace, groupName, resKind, resName)
			if allowed {
				return true
			}
		case commonBean.JobKind:
			// check CronJob first, then Job
			if strings.Contains(resName, "-") {
				cronJobName := resName[:strings.LastIndex(resName, "-")]
				allowed := validateCallback(namespace, groupName, commonBean.K8sClusterResourceCronJobKind, cronJobName)
				if allowed {
					return true
				}
			}
			allowed := validateCallback(namespace, groupName, resKind, resName)
			if allowed {
				return true
			}
		case commonBean.DeploymentKind, commonBean.K8sClusterResourceCronJobKind, commonBean.StatefulSetKind,
			commonBean.DaemonSetKind, commonBean.K8sClusterResourceRolloutKind, commonBean.K8sClusterResourceReplicationControllerKind:
			allowed := validateCallback(namespace, groupName, resKind, resName)
			if allowed {
				return true
			}
		}
	}
	return false
}

func (impl *K8sServiceImpl) GetKubeVersion() (*version.Info, error) {
	discoveryClient, err := impl.GetK8sDiscoveryClientInCluster()
	if err != nil {
		impl.logger.Errorw("eexception caught in getting discoveryClient", "err", err)
		return nil, err
	}
	k8sServerVersion, err := discoveryClient.ServerVersion()
	if err != nil {
		impl.logger.Errorw("exception caught in getting k8sServerVersion", "err", err)
		return nil, err
	}
	return k8sServerVersion, err
}

func (impl *K8sServiceImpl) GetCoreV1ClientInCluster(opts ...K8sServiceOpts) (*v12.CoreV1Client, error) {
	restConfig := &rest.Config{}
	restConfig, err := impl.GetK8sInClusterRestConfig(opts...)
	if err != nil {
		impl.logger.Error("Error in creating config for default cluster", "err", err)
		return nil, err
	}
	return impl.GetCoreV1ClientByRestConfig(restConfig)
}

func (impl *K8sServiceImpl) GetCoreV1ClientByRestConfig(restConfig *rest.Config) (*v12.CoreV1Client, error) {
	httpClientFor, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		impl.logger.Error("error occurred while overriding k8s client", "reason", err)
		return nil, err
	}
	k8sClient, err := v12.NewForConfigAndClient(restConfig, httpClientFor)
	if err != nil {
		impl.logger.Error("error creating k8s client", "error", err)
		return nil, err
	}
	return k8sClient, err
}

func (impl *K8sServiceImpl) GetNodesList(ctx context.Context, k8sClientSet *kubernetes.Clientset) (*v1.NodeList, error) {
	nodeList, err := k8sClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting node list", "err", err)
		return nil, err
	}
	return nodeList, err
}

func (impl *K8sServiceImpl) GetNodeByName(ctx context.Context, k8sClientSet *kubernetes.Clientset, name string) (*v1.Node, error) {
	node, err := k8sClientSet.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting node by name", "err", err)
		return nil, err
	}
	return node, err
}

func (impl *K8sServiceImpl) GetServerVersionFromDiscoveryClient(k8sClientSet *kubernetes.Clientset) (*version.Info, error) {
	serverVersion, err := k8sClientSet.DiscoveryClient.ServerVersion()
	if err != nil {
		impl.logger.Errorw("error in getting  server version from discovery client", "err", err)
		return nil, err
	}
	return serverVersion, err
}

func (impl *K8sServiceImpl) GetServerGroups(k8sClientSet *kubernetes.Clientset) (*metav1.APIGroupList, error) {
	serverGroups, err := k8sClientSet.DiscoveryClient.ServerGroups()
	if err != nil {
		impl.logger.Errorw("error in retrieving server groups", "err", err)
		return nil, err
	} else if serverGroups == nil {
		impl.logger.Errorw("server groups are empty", "err", err)
		return nil, NotFoundError
	}
	return serverGroups, nil
}

func (impl *K8sServiceImpl) GetPodsListForNamespace(ctx context.Context, k8sClientSet *kubernetes.Clientset, namespace string) (*v1.PodList, error) {
	podList, err := k8sClientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting pos list for namespace", "err", err)
		return nil, err
	}
	return podList, err
}

func (impl *K8sServiceImpl) GetNmList(ctx context.Context, metricsClientSet *metrics.Clientset) (*v1beta1.NodeMetricsList, error) {
	nmList, err := metricsClientSet.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting node metrics", "err", err)
		return nil, err
	}
	return nmList, err
}

func (impl *K8sServiceImpl) GetNmByName(ctx context.Context, metricsClientSet *metrics.Clientset, name string) (*v1beta1.NodeMetrics, error) {
	nodeMetrics, err := metricsClientSet.MetricsV1beta1().NodeMetricses().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("error in getting node metrics by name", "err", err)
		return nil, err
	}
	return nodeMetrics, err
}

func (impl *K8sServiceImpl) GetMetricsClientSet(restConfig *rest.Config, k8sHttpClient *http.Client) (*metrics.Clientset, error) {
	metricsClientSet, err := metrics.NewForConfigAndClient(restConfig, k8sHttpClient)
	if err != nil {
		impl.logger.Errorw("error in getting metrics client set", "err", err)
		return nil, err
	}
	return metricsClientSet, err
}

func (impl *K8sServiceImpl) GetLogsForAPod(kubeClient *kubernetes.Clientset, namespace string, podName string, container string, follow bool) *rest.Request {
	podLogOpts := &v1.PodLogOptions{
		Container: container,
		Follow:    follow,
	}
	req := kubeClient.CoreV1().Pods(namespace).GetLogs(podName, podLogOpts)
	return req
}

func (impl *K8sServiceImpl) CreateK8sClientSet(restConfig *rest.Config) (*kubernetes.Clientset, error) {
	k8sHttpClient, err := OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		impl.logger.Errorw("service err, OverrideK8sHttpClientWithTracer", "err", err)
		return nil, err
	}
	k8sClientSet, err := kubernetes.NewForConfigAndClient(restConfig, k8sHttpClient)
	if err != nil {
		impl.logger.Errorw("error in getting client set by rest config", "err", err)
		return nil, err
	}
	return k8sClientSet, err
}

func (impl *K8sServiceImpl) FetchConnectionStatusForCluster(k8sClientSet *kubernetes.Clientset) error {
	//using livez path as healthz path is deprecated
	path := commonBean.LiveZ
	response, err := k8sClientSet.Discovery().RESTClient().Get().AbsPath(path).DoRaw(context.Background())
	log.Println("received response for cluster livez status", "response", string(response), "err", err)
	if err != nil {
		if _, ok := err.(*url.Error); ok {
			err = fmt.Errorf("Incorrect server url : %v", err)
		} else if statusError, ok := err.(*errors.StatusError); ok {
			if statusError != nil {
				errReason := statusError.ErrStatus.Reason
				var errMsg string
				if errReason == metav1.StatusReasonUnauthorized {
					errMsg = "token seems invalid or does not have sufficient permissions"
				} else {
					errMsg = statusError.ErrStatus.Message
				}
				err = fmt.Errorf("%s : %s", errReason, errMsg)
			} else {
				err = fmt.Errorf("Validation failed : %v", err)
			}
		} else {
			err = fmt.Errorf("Validation failed : %v", err)
		}
	} else if err == nil && string(response) != "ok" {
		err = fmt.Errorf("Validation failed with response : %s", string(response))
	}
	return err
}

func (impl *K8sServiceImpl) GetResourceIf(restConfig *rest.Config, groupVersionKind schema.GroupVersionKind) (resourceIf dynamic.NamespaceableResourceInterface, namespaced bool, err error) {
	httpClient, err := OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		return nil, false, err
	}
	dynamicIf, err := dynamic.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err)
		return nil, false, err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting k8s client", "err", err)
		return nil, false, err
	}
	apiResource, err := ServerResourceForGroupVersionKind(discoveryClient, groupVersionKind)
	if err != nil {
		impl.logger.Errorw("error in getting server resource", "err", err)
		return nil, false, err
	}
	resource := groupVersionKind.GroupVersion().WithResource(apiResource.Name)
	return dynamicIf.Resource(resource), apiResource.Namespaced, nil
}

func (impl *K8sServiceImpl) ListEvents(restConfig *rest.Config, namespace string, groupVersionKind schema.GroupVersionKind, ctx context.Context, name string) (*v1.EventList, error) {
	_, namespaced, err := impl.GetResourceIf(restConfig, groupVersionKind)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "resource", name)
		return nil, err
	}

	if !namespaced {
		namespace = "default"
	}
	httpClient, err := OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting http client", "err", err)
		return nil, err
	}
	eventsClient, err := v12.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting client for resource", "err", err, "resource", name)
		return nil, err
	}
	eventsIf := eventsClient.Events(namespace)
	eventsExp := eventsIf.(v12.EventExpansion)
	fieldSelector := eventsExp.GetFieldSelector(pointer.StringPtr(name), pointer.StringPtr(namespace), pointer.StringPtr(groupVersionKind.Kind), nil)
	listOptions := metav1.ListOptions{
		TypeMeta: metav1.TypeMeta{
			Kind:       "List",
			APIVersion: groupVersionKind.GroupVersion().String(),
		},
		FieldSelector: fieldSelector.String(),
	}
	list, err := eventsIf.List(ctx, listOptions)
	if err != nil {
		impl.logger.Errorw("error in getting events list", "err", err, "resource", name)
		return nil, err
	}
	return list, err

}

func (impl *K8sServiceImpl) GetPodLogs(ctx context.Context, restConfig *rest.Config, name string, namespace string, sinceTime *metav1.Time, tailLines int, sinceSeconds int, follow bool, containerName string, isPrevContainerLogsEnabled bool) (io.ReadCloser, error) {
	httpClient, err := OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting pod logs", "err", err)
		return nil, err
	}
	podClient, err := v12.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting client for resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	TailLines := int64(tailLines)
	SinceSeconds := int64(sinceSeconds)
	podLogOptions := &v1.PodLogOptions{
		Follow:     follow,
		Container:  containerName,
		Timestamps: true,
		Previous:   isPrevContainerLogsEnabled,
	}
	startTime := metav1.Unix(0, 0)
	if TailLines > 0 {
		podLogOptions.TailLines = &TailLines
	}
	if SinceSeconds > 0 {
		podLogOptions.SinceSeconds = &SinceSeconds
	}
	if *sinceTime != startTime {
		podLogOptions.SinceTime = sinceTime
	}
	podIf := podClient.Pods(namespace)
	logsRequest := podIf.GetLogs(name, podLogOptions)
	stream, err := logsRequest.Stream(ctx)
	if err != nil {
		impl.logger.Errorw("error in streaming pod logs", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	return stream, nil
}

func (impl *K8sServiceImpl) GetResourceIfWithAcceptHeader(restConfig *rest.Config, groupVersionKind schema.GroupVersionKind, asTable bool) (resourceIf dynamic.NamespaceableResourceInterface, namespaced bool, err error) {
	httpClient, err := OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting http client", "err", err)
		return nil, false, err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting k8s client", "err", err)
		return nil, false, err
	}
	apiResource, err := ServerResourceForGroupVersionKind(discoveryClient, groupVersionKind)
	if err != nil {
		impl.logger.Errorw("error in getting server resource", "err", err)
		return nil, false, err
	}
	resource := groupVersionKind.GroupVersion().WithResource(apiResource.Name)
	wt := restConfig.WrapTransport // Reference: https://github.com/kubernetes/client-go/issues/407
	if asTable {
		restConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			if wt != nil {
				rt = wt(rt)
			}
			return &http2.HeaderAdder{
				Rt: rt,
			}
		}
	}
	httpClient, err = OverrideK8sHttpClientWithTracer(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting http client", "err", err)
		return nil, false, err
	}
	dynamicIf, err := dynamic.NewForConfigAndClient(restConfig, httpClient)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err)
		return nil, false, err
	}
	return dynamicIf.Resource(resource), apiResource.Namespaced, nil
}

func (impl *K8sServiceImpl) GetResourceList(ctx context.Context, restConfig *rest.Config, gvk schema.GroupVersionKind, namespace string, asTable bool, listOptions *metav1.ListOptions) (*ResourceListResponse, bool, error) {
	resourceIf, namespaced, err := impl.GetResourceIfWithAcceptHeader(restConfig, gvk, asTable)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "namespace", namespace)
		return nil, namespaced, err
	}
	var resp *unstructured.UnstructuredList
	if listOptions == nil {
		listOptions = &metav1.ListOptions{
			TypeMeta: metav1.TypeMeta{
				Kind:       gvk.Kind,
				APIVersion: gvk.GroupVersion().String(),
			},
		}
	}
	if len(namespace) > 0 && namespaced {
		resp, err = resourceIf.Namespace(namespace).List(ctx, *listOptions)
	} else {
		resp, err = resourceIf.List(ctx, *listOptions)
	}
	if err != nil {
		impl.logger.Errorw("error in getting resource", "err", err, "namespace", namespace)
		return nil, namespaced, err
	}
	return &ResourceListResponse{*resp}, namespaced, nil

}

func (impl *K8sServiceImpl) PatchResourceRequest(ctx context.Context, restConfig *rest.Config, pt types.PatchType, manifest string, name string, namespace string, gvk schema.GroupVersionKind) (*ManifestResponse, error) {
	resourceIf, namespaced, err := impl.GetResourceIf(restConfig, gvk)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}

	var resp *unstructured.Unstructured
	if len(namespace) > 0 && namespaced {
		resp, err = resourceIf.Namespace(namespace).Patch(ctx, name, pt, []byte(manifest), metav1.PatchOptions{FieldManager: "patch"})
	} else {
		resp, err = resourceIf.Patch(ctx, name, pt, []byte(manifest), metav1.PatchOptions{FieldManager: "patch"})
	}
	if err != nil {
		impl.logger.Errorw("error in applying resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	return &ManifestResponse{Manifest: *resp}, nil
}

// GetApiResources returns the list of api resources from k8s.
// if verb is supplied empty, that means - return all
func (impl *K8sServiceImpl) GetApiResources(restConfig *rest.Config, includeOnlyVerb string) ([]*K8sApiResource, error) {
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic k8s client", "err", err)
		return nil, err
	}

	apiResourcesListFromK8s, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		//takes care when K8s is unable to handle the request for some resources
		Isk8sApiError := strings.Contains(err.Error(), "unable to retrieve the complete list of server APIs")
		switch Isk8sApiError {
		case true:
			break
		default:
			impl.logger.Errorw("error in getting api-resources from k8s", "err", err)
			return nil, err
		}
	}

	apiResources := make([]*K8sApiResource, 0)
	for _, apiResourceListFromK8s := range apiResourcesListFromK8s {
		if apiResourceListFromK8s != nil {
			for _, apiResourceFromK8s := range apiResourceListFromK8s.APIResources {
				var includeResource bool
				if len(includeOnlyVerb) > 0 {
					for _, verb := range apiResourceFromK8s.Verbs {
						if verb == includeOnlyVerb {
							includeResource = true
							break
						}
					}
				} else {
					includeResource = true
				}
				if !includeResource {
					continue
				}
				var group string
				var version string
				gv := apiResourceListFromK8s.GroupVersion
				if len(gv) > 0 {
					splitGv := strings.Split(gv, "/")
					if len(splitGv) == 1 {
						version = splitGv[0]
					} else {
						group = splitGv[0]
						version = splitGv[1]
					}
				}
				apiResources = append(apiResources, &K8sApiResource{
					Gvk: schema.GroupVersionKind{
						Group:   group,
						Version: version,
						Kind:    apiResourceFromK8s.Kind,
					},
					Gvr: schema.GroupVersionResource{
						Group:    group,
						Version:  version,
						Resource: apiResourceFromK8s.Name,
					},
					Namespaced: apiResourceFromK8s.Namespaced,
					ShortNames: apiResourceFromK8s.ShortNames,
				})
			}
		}
	}
	return apiResources, nil
}

func (impl *K8sServiceImpl) CreateResources(ctx context.Context, restConfig *rest.Config, manifest string, gvk schema.GroupVersionKind, namespace string) (*ManifestResponse, error) {
	resourceIf, namespaced, err := impl.GetResourceIf(restConfig, gvk)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "namespace", namespace)
		return nil, err
	}
	var createObj map[string]interface{}
	err = json.Unmarshal([]byte(manifest), &createObj)
	if err != nil {
		impl.logger.Errorw("error in json un-marshaling patch(manifest) string for creating resource", "err", err, "namespace", namespace)
		return nil, err
	}
	var resp *unstructured.Unstructured
	if len(namespace) > 0 && namespaced {
		resp, err = resourceIf.Namespace(namespace).Create(ctx, &unstructured.Unstructured{Object: createObj}, metav1.CreateOptions{})
	} else {
		resp, err = resourceIf.Create(ctx, &unstructured.Unstructured{Object: createObj}, metav1.CreateOptions{})
	}
	if err != nil {
		impl.logger.Errorw("error in creating resource", "err", err, "namespace", namespace)
		return nil, err
	}
	return &ManifestResponse{Manifest: *resp}, nil
}

func (impl *K8sServiceImpl) GetResource(ctx context.Context, namespace string, name string, gvk schema.GroupVersionKind, restConfig *rest.Config) (*ManifestResponse, error) {
	resourceIf, namespaced, err := impl.GetResourceIf(restConfig, gvk)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "namespace", namespace)
		return nil, err
	}
	var resp *unstructured.Unstructured
	if len(namespace) > 0 && namespaced {
		resp, err = resourceIf.Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		resp, err = resourceIf.Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		impl.logger.Errorw("error in getting resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	return &ManifestResponse{Manifest: *resp}, nil
}

func (impl *K8sServiceImpl) UpdateResource(ctx context.Context, restConfig *rest.Config, gvk schema.GroupVersionKind, namespace string, k8sRequestPatch string) (*ManifestResponse, error) {
	resourceIf, namespaced, err := impl.GetResourceIf(restConfig, gvk)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "namespace", namespace)
		return nil, err
	}
	var updateObj map[string]interface{}
	err = json.Unmarshal([]byte(k8sRequestPatch), &updateObj)
	if err != nil {
		impl.logger.Errorw("error in json un-marshaling patch string for updating resource ", "err", err, "namespace", namespace)
		return nil, err
	}
	var resp *unstructured.Unstructured
	if len(namespace) > 0 && namespaced {
		resp, err = resourceIf.Namespace(namespace).Update(ctx, &unstructured.Unstructured{Object: updateObj}, metav1.UpdateOptions{})
	} else {
		resp, err = resourceIf.Update(ctx, &unstructured.Unstructured{Object: updateObj}, metav1.UpdateOptions{})
	}
	if err != nil {
		impl.logger.Errorw("error in updating resource", "err", err, "namespace", namespace)
		return nil, err
	}
	return &ManifestResponse{Manifest: *resp}, nil
}

func (impl *K8sServiceImpl) DeleteResource(ctx context.Context, restConfig *rest.Config, gvk schema.GroupVersionKind, namespace string, name string, forceDelete bool) (*ManifestResponse, error) {
	resourceIf, namespaced, err := impl.GetResourceIf(restConfig, gvk)
	if err != nil {
		impl.logger.Errorw("error in getting dynamic interface for resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	var obj *unstructured.Unstructured
	deleteOptions := metav1.DeleteOptions{}
	if forceDelete {
		deleteOptions.GracePeriodSeconds = pointer.Int64Ptr(0)
	}
	if len(namespace) > 0 && namespaced {
		obj, err = resourceIf.Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			impl.logger.Errorw("error in getting resource", "err", err, "resource", name, "namespace", namespace)
			return nil, err
		}
		err = resourceIf.Namespace(namespace).Delete(ctx, name, deleteOptions)
	} else {
		obj, err = resourceIf.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			impl.logger.Errorw("error in getting resource", "err", err, "resource", name, "namespace", namespace)
			return nil, err
		}
		err = resourceIf.Delete(ctx, name, deleteOptions)
	}
	if err != nil {
		impl.logger.Errorw("error in deleting resource", "err", err, "resource", name, "namespace", namespace)
		return nil, err
	}
	return &ManifestResponse{Manifest: *obj}, nil
}

func (impl *K8sServiceImpl) DecodeGroupKindversion(data string) (*schema.GroupVersionKind, error) {
	_, groupVersionKind, err := legacyscheme.Codecs.UniversalDeserializer().Decode([]byte(data), nil, nil)
	if err != nil {
		impl.logger.Errorw("error occurred while extracting data for gvk", "err", err, "gvk", data)
		return nil, err
	}
	return groupVersionKind, err
}

func (impl *K8sServiceImpl) GetK8sServerVersion(clientSet *kubernetes.Clientset) (*version.Info, error) {
	k8sServerVersion, err := clientSet.DiscoveryClient.ServerVersion()
	if err != nil {
		impl.logger.Errorw("error occurred in getting k8sServerVersion", "err", err)
		return nil, err
	}
	return k8sServerVersion, nil
}

func (impl *K8sServiceImpl) ExtractK8sServerMajorAndMinorVersion(k8sServerVersion *version.Info) (int, int, error) {
	majorVersion, err := strconv.Atoi(k8sServerVersion.Major)
	if err != nil {
		impl.logger.Errorw("error occurred in converting k8sServerVersion.Major version value to integer", "err", err, "k8sServerVersion.Major", k8sServerVersion.Major)
		return 0, 0, err
	}
	minorVersion, err := strconv.Atoi(k8sServerVersion.Minor)
	if err != nil {
		impl.logger.Errorw("error occurred in converting k8sServerVersion.Minor version value to integer", "err", err, "k8sServerVersion.Minor", k8sServerVersion.Minor)
		return majorVersion, 0, err
	}
	return majorVersion, minorVersion, nil
}

func (impl *K8sServiceImpl) GetPodListByLabel(namespace, label string, clientSet *kubernetes.Clientset) ([]v1.Pod, error) {
	pods := clientSet.CoreV1().Pods(namespace)
	podList, err := pods.List(context.Background(), metav1.ListOptions{LabelSelector: label})
	if err != nil {
		impl.logger.Errorw("get pod err, DeletePod", "err", err)
		return nil, err
	}
	return podList.Items, nil
}

func (impl *K8sServiceImpl) CreateOrUpdateSecretByName(client *v12.CoreV1Client, namespace, uniqueSecretName string, secretLabel map[string]string, secretData map[string]string) error {

	secret, err := impl.GetSecret(namespace, uniqueSecretName, client)
	statusError, ok := err.(*errors.StatusError)
	if err != nil && (ok && statusError != nil && statusError.Status().Code != http.StatusNotFound) {
		impl.logger.Errorw("error in fetching secret", "err", err)
		return err
	}

	if ok && statusError != nil && statusError.Status().Code == http.StatusNotFound {
		_, err = impl.CreateSecret(namespace, nil, uniqueSecretName, "", client, secretLabel, secretData)
		if err != nil {
			impl.logger.Errorw("Error in creating secret for chart repo", "uniqueSecretName", uniqueSecretName, "err", err)
			return err
		}
	} else {
		secret.StringData = secretData
		_, err = impl.UpdateSecret(namespace, secret, client)
		if err != nil {
			impl.logger.Errorw("Error in creating secret for chart repo", "uniqueSecretName", uniqueSecretName, "err", err)
			return err
		}
	}
	return nil
}

func (impl *K8sServiceImpl) GetResourceByGVR(ctx context.Context, config *rest.Config, GVR schema.GroupVersionResource, resourceName, namespace string) (*unstructured.Unstructured, error) {
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		impl.logger.Errorw("failed to create dynamic client", "err", err)
		return nil, err
	}
	resource, err := dynClient.Resource(GVR).Namespace(namespace).Get(ctx, resourceName, metav1.GetOptions{})
	if err != nil {
		impl.logger.Errorw("failed to get resource", "resourceName", resourceName, "namespace", namespace, "err", err)
		return nil, err
	}
	return resource, nil
}

func (impl *K8sServiceImpl) PatchResourceByGVR(ctx context.Context, config *rest.Config, GVR schema.GroupVersionResource, resourceName, namespace string, patchType types.PatchType, patchData []byte) (*unstructured.Unstructured, error) {
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		impl.logger.Errorw("failed to create dynamic client", "err", err)
		return nil, err
	}
	resource, err := dynClient.Resource(GVR).Namespace(namespace).Patch(ctx, resourceName, patchType, patchData, metav1.PatchOptions{FieldManager: "patch"})
	if err != nil {
		impl.logger.Errorw("failed to get resource", "resourceName", resourceName, "namespace", namespace, "err", err)
		return nil, err
	}
	return resource, nil
}

func (impl *K8sServiceImpl) DeleteResourceByGVR(ctx context.Context, config *rest.Config, GVR schema.GroupVersionResource, resourceName, namespace string, forceDelete bool) error {
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		impl.logger.Errorw("failed to create dynamic client", "err", err)
		return err
	}
	deleteOptions := metav1.DeleteOptions{}
	if forceDelete {
		deleteOptions.GracePeriodSeconds = pointer.Int64Ptr(0)
	}
	err = dynClient.Resource(GVR).Namespace(namespace).Delete(ctx, resourceName, deleteOptions)
	if err != nil {
		impl.logger.Errorw("failed to get resource", "resourceName", resourceName, "namespace", namespace, "err", err)
		return err
	}
	return nil
}

func (impl *K8sServiceImpl) GetK8sInClusterRestConfig(opts ...K8sServiceOpts) (*rest.Config, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetK8sInClusterRestConfig()
}

func (impl *K8sServiceImpl) GetK8sConfigAndClients(clusterConfig *ClusterConfig, opts ...K8sServiceOpts) (*rest.Config, *http.Client, *kubernetes.Clientset, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetK8sConfigAndClients(clusterConfig)
}

func (impl *K8sServiceImpl) GetK8sInClusterConfigAndDynamicClients(opts ...K8sServiceOpts) (*rest.Config, *http.Client, dynamic.Interface, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetK8sInClusterConfigAndDynamicClients()
}

func (impl *K8sServiceImpl) GetK8sInClusterConfigAndClients(opts ...K8sServiceOpts) (*rest.Config, *http.Client, *kubernetes.Clientset, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetK8sInClusterConfigAndClients()
}

func (impl *K8sServiceImpl) GetRestConfigByCluster(clusterConfig *ClusterConfig, opts ...K8sServiceOpts) (*rest.Config, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetRestConfigByCluster(clusterConfig)
}

func (impl *K8sServiceImpl) OverrideRestConfigWithCustomTransport(restConfig *rest.Config, opts ...K8sServiceOpts) (*rest.Config, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).OverrideRestConfigWithCustomTransport(restConfig)
}

func (impl *K8sServiceImpl) GetK8sConfigAndClientsByRestConfig(restConfig *rest.Config, opts ...K8sServiceOpts) (*http.Client, *kubernetes.Clientset, error) {
	return impl.WithHttpTransport(impl.getOpts(opts)).GetK8sConfigAndClientsByRestConfig(restConfig)
}

func (impl *K8sServiceImpl) DeleteNs(namespace string, client *v12.CoreV1Client) error {
	err := client.Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	return err
}

func (impl *K8sServiceImpl) getEventKindHeader() ([]string, map[int]string) {
	headers := []string{"type", "message", "namespace", "involved object", "source", "count", "age", "last seen"}
	columnIndexes := make(map[int]string)
	columnIndexes[0] = "last seen"
	columnIndexes[1] = "type"
	columnIndexes[2] = "namespace"
	columnIndexes[3] = "involved object"
	columnIndexes[5] = "source"
	columnIndexes[6] = "message"
	columnIndexes[7] = "age"
	columnIndexes[8] = "count"
	return headers, columnIndexes
}

func (impl *K8sServiceImpl) GetGVRForCRD(config *rest.Config, CRDName string) (schema.GroupVersionResource, error) {
	apiExtClient, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		impl.logger.Error("error in getting api extension client", "err", err)
		return schema.GroupVersionResource{}, err
	}
	crd, err := apiExtClient.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), CRDName, metav1.GetOptions{})
	if err != nil {
		impl.logger.Error("error in getting terraform crd", "err", err)
		return schema.GroupVersionResource{}, err
	}
	var servedVersion string
	for _, v := range crd.Spec.Versions {
		if v.Served {
			servedVersion = v.Name
			break
		}
	}
	return schema.GroupVersionResource{
		Group:    crd.Spec.Group,
		Version:  servedVersion,
		Resource: crd.Spec.Names.Plural,
	}, nil
}

func (impl *K8sServiceImpl) GetRestClientForCRD(config *ClusterConfig, groupVersion *schema.GroupVersion) (*rest.RESTClient, error) {

	restConfig, err := impl.GetRestConfigByCluster(config)
	if err != nil {
		return nil, err
	}

	restConfig.ContentConfig = rest.ContentConfig{
		GroupVersion:         groupVersion,
		NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
	}
	restConfig.APIPath = "/apis"

	restClient, err := rest.RESTClientFor(restConfig)
	if err != nil {
		impl.logger.Errorw("error in getting rest client", "gvr", groupVersion.String(), "err", err)
		return nil, err
	}

	return restClient, nil
}

func (impl *K8sServiceImpl) PatchResourceByRestClient(restClient *rest.RESTClient, resource, name, namespace string, pt types.PatchType, data []byte, subresources ...string) rest.Result {
	result := restClient.Patch(pt).
		Namespace(namespace).
		Resource(resource).
		Name(name).
		SubResource(subresources...).
		Body(data).
		Do(context.Background())
	return result
}
