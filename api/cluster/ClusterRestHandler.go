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

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	bean2 "github.com/devtron-labs/devtron/pkg/cluster/bean"
	"github.com/devtron-labs/devtron/pkg/cluster/environment"
	"github.com/devtron-labs/devtron/pkg/cluster/rbac"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devtron-labs/devtron/pkg/auth/authorisation/casbin"
	"github.com/devtron-labs/devtron/pkg/auth/user"
	"github.com/devtron-labs/devtron/pkg/genericNotes"
	"github.com/devtron-labs/devtron/pkg/genericNotes/repository"

	"github.com/devtron-labs/devtron/api/restHandler/common"
	"github.com/devtron-labs/devtron/pkg/cluster"
	delete2 "github.com/devtron-labs/devtron/pkg/delete"
	util2 "github.com/devtron-labs/devtron/util"
	"github.com/go-pg/pg"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"
)

const CLUSTER_DELETE_SUCCESS_RESP = "Cluster deleted successfully."

type ClusterRestHandler interface {
	Save(w http.ResponseWriter, r *http.Request)
	SaveClusters(w http.ResponseWriter, r *http.Request)
	ValidateKubeconfig(w http.ResponseWriter, r *http.Request)
	FindAll(w http.ResponseWriter, r *http.Request)
	FindById(w http.ResponseWriter, r *http.Request)
	FindNoteByClusterId(w http.ResponseWriter, r *http.Request)
	Update(w http.ResponseWriter, r *http.Request)
	UpdateClusterDescription(w http.ResponseWriter, r *http.Request)
	UpdateClusterNote(w http.ResponseWriter, r *http.Request)
	FindAllForAutoComplete(w http.ResponseWriter, r *http.Request)
	DeleteCluster(w http.ResponseWriter, r *http.Request)
	GetClusterNamespaces(w http.ResponseWriter, r *http.Request)
	GetAllClusterNamespaces(w http.ResponseWriter, r *http.Request)
	FindAllForClusterPermission(w http.ResponseWriter, r *http.Request)
}

type ClusterRestHandlerImpl struct {
	clusterService            cluster.ClusterService
	clusterNoteService        genericNotes.GenericNoteService
	clusterDescriptionService cluster.ClusterDescriptionService
	logger                    *zap.SugaredLogger
	userService               user.UserService
	validator                 *validator.Validate
	enforcer                  casbin.Enforcer
	deleteService             delete2.DeleteService
	environmentService        environment.EnvironmentService
	clusterRbacService        rbac.ClusterRbacService
}

func NewClusterRestHandlerImpl(clusterService cluster.ClusterService,
	clusterNoteService genericNotes.GenericNoteService,
	clusterDescriptionService cluster.ClusterDescriptionService,
	logger *zap.SugaredLogger,
	userService user.UserService,
	validator *validator.Validate,
	enforcer casbin.Enforcer,
	deleteService delete2.DeleteService,
	environmentService environment.EnvironmentService,
	clusterRbacService rbac.ClusterRbacService) *ClusterRestHandlerImpl {
	return &ClusterRestHandlerImpl{
		clusterService:            clusterService,
		clusterNoteService:        clusterNoteService,
		clusterDescriptionService: clusterDescriptionService,
		logger:                    logger,
		userService:               userService,
		validator:                 validator,
		enforcer:                  enforcer,
		deleteService:             deleteService,
		environmentService:        environmentService,
		clusterRbacService:        clusterRbacService,
	}
}

func (impl ClusterRestHandlerImpl) SaveClusters(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	beans := []*bean2.ClusterBean{}
	err = decoder.Decode(&beans)
	if err != nil {
		impl.logger.Errorw("request err, Save", "error", err, "payload", beans)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	// not logging bean object as it contains sensitive data
	impl.logger.Infow("request payload received for save clusters")

	// RBAC enforcer applying
	if ok := impl.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionCreate, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized User"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends
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
	if util2.IsBaseStack() {
		ctx = context.WithValue(ctx, "token", token)
	}

	for _, bean := range beans {
		l := len(bean.ServerUrl)
		if l > 1 && bean.ServerUrl[l-1:] == "/" {
			bean.ServerUrl = bean.ServerUrl[0 : l-1]
		}
		if bean.Id != 0 {
			_, err1 := impl.clusterService.Update(ctx, bean, userId)
			if err1 != nil {
				bean.ErrorInConnecting = err1.Error()
			} else {
				bean.ClusterUpdated = true
			}
		} else {
			_, err1 := impl.clusterService.Save(ctx, bean, userId)
			if err1 != nil {
				bean.ErrorInConnecting = err1.Error()
			}
		}
	}

	res := beans

	common.WriteJsonResp(w, err, res, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) Save(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	bean := new(bean2.ClusterBean)
	err = decoder.Decode(bean)
	if err != nil {
		impl.logger.Errorw("request err, Save", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	impl.logger.Infow("request payload, Save", "payload", bean)
	err = impl.validator.Struct(bean)
	if err != nil {
		impl.logger.Errorw("validation err, Save", "err", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC enforcer applying
	if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionCreate, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends
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
	if util2.IsBaseStack() {
		ctx = context.WithValue(ctx, "token", token)
	}
	bean, err = impl.clusterService.Save(ctx, bean, userId)
	if err != nil {
		impl.logger.Errorw("service err, Save", "err", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	/*	isTriggered, err := impl.installedAppService.DeployDefaultChartOnCluster(bean, userId)
		if err != nil {
			impl.logger.Errorw("service err, Save, on DeployDefaultChartOnCluster", "err", err, "payload", bean)
		}
		if isTriggered {
			bean.AgentInstallationStage = 1
		} else {
			bean.AgentInstallationStage = 0
		}*/
	common.WriteJsonResp(w, err, bean, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) ValidateKubeconfig(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	bean := &bean2.Kubeconfig{}
	err = decoder.Decode(bean)
	if err != nil {
		impl.logger.Errorw("request err, Validate", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	err = impl.validator.Struct(bean)
	if err != nil {
		impl.logger.Errorw("validation err, Validate", "err", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC enforcer applying
	if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionCreate, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends
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
	if util2.IsBaseStack() {
		ctx = context.WithValue(ctx, "token", token)
	}
	res, err := impl.clusterService.ValidateKubeconfig(bean.Config)
	if err != nil {
		impl.logger.Errorw("error in validating kubeconfig")
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	common.WriteJsonResp(w, err, res, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) FindAll(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	clusterList, err := impl.clusterService.FindAllWithoutConfig()
	if err != nil {
		impl.logger.Errorw("service err, FindAll", "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	// RBAC enforcer applying
	var result []*bean2.ClusterBean
	for _, item := range clusterList {
		if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionGet, item.ClusterName); ok {
			result = append(result, item)
		}
	}
	//RBAC enforcer Ends

	common.WriteJsonResp(w, err, result, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) FindById(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	i, err := strconv.Atoi(id)
	if err != nil {
		impl.logger.Errorw("request err, FindById", "error", err, "clusterId", id)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	bean, err := impl.clusterService.FindByIdWithoutConfig(i)
	if err != nil {
		impl.logger.Errorw("service err, FindById", "err", err, "clusterId", id)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	// RBAC enforcer applying
	token := r.Header.Get("token")
	if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionGet, bean.ClusterName); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends

	common.WriteJsonResp(w, err, bean, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) FindNoteByClusterId(w http.ResponseWriter, r *http.Request) {
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	clusterId, err := strconv.Atoi(id)
	if err != nil {
		impl.logger.Errorw("request err, FindById", "error", err, "clusterId", id)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	bean, err := impl.clusterDescriptionService.FindByClusterIdWithClusterDetails(clusterId)
	if err != nil {
		if err == pg.ErrNoRows {
			impl.logger.Errorw("cluster not found, FindById", "err", err, "clusterId", id)
			common.WriteJsonResp(w, errors.New("invalid cluster id"), nil, http.StatusNotFound)
			return
		}
		impl.logger.Errorw("service err, FindById", "err", err, "clusterId", id)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	// RBAC enforcer applying
	token := r.Header.Get("token")
	authenticated, err := impl.clusterRbacService.CheckAuthorization(bean.ClusterName, bean.ClusterId, token, userId, true)
	if err != nil {
		impl.logger.Errorw("error in checking rbac for cluster", "err", err, "clusterId", bean.ClusterId)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	if !authenticated {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends
	common.WriteJsonResp(w, err, bean, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) Update(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("service err, Update", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var bean bean2.ClusterBean
	err = decoder.Decode(&bean)
	if err != nil {
		impl.logger.Errorw("request err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	impl.logger.Infow("request payload, Update", "payload", bean)
	err = impl.validator.Struct(bean)
	if err != nil {
		impl.logger.Errorw("validate err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC enforcer applying
	if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionUpdate, bean.ClusterName); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	// RBAC enforcer ends
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
	if util2.IsBaseStack() {
		ctx = context.WithValue(ctx, "token", token)
	}
	_, err = impl.clusterService.Update(ctx, &bean, userId)
	if err != nil {
		impl.logger.Errorw("service err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}

	common.WriteJsonResp(w, err, bean, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) UpdateClusterDescription(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("service err, Update", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var bean bean2.ClusterBean
	err = decoder.Decode(&bean)
	if err != nil {
		impl.logger.Errorw("request err, UpdateClusterDescription", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	impl.logger.Infow("request payload, UpdateClusterDescription", "payload", bean)
	//TODO: add apt validation
	clusterDescription, err := impl.clusterDescriptionService.FindByClusterIdWithClusterDetails(bean.Id)
	if err != nil {
		impl.logger.Errorw("service err, FindById", "err", err, "clusterId", bean.Id)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	// RBAC enforcer applying
	authenticated := impl.clusterRbacService.CheckAuthorisationForAllK8sPermissions(token, clusterDescription.ClusterName, casbin.ActionUpdate)
	if !authenticated {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	// RBAC enforcer ends
	err = impl.clusterService.UpdateClusterDescription(&bean, userId)
	if err != nil {
		impl.logger.Errorw("service err, UpdateClusterDescription", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, "Cluster description updated successfully", http.StatusOK)
}

func (impl ClusterRestHandlerImpl) UpdateClusterNote(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("service err, Update", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var bean repository.GenericNote
	err = decoder.Decode(&bean)
	if err != nil {
		impl.logger.Errorw("request err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	impl.logger.Infow("request payload, Update", "payload", bean)
	err = impl.validator.Struct(bean)
	if err != nil {
		impl.logger.Errorw("validate err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	clusterDescription, err := impl.clusterDescriptionService.FindByClusterIdWithClusterDetails(bean.Identifier)
	if err != nil {
		impl.logger.Errorw("service err, FindById", "err", err, "clusterId", bean.Identifier)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	// RBAC enforcer applying
	authenticated := impl.clusterRbacService.CheckAuthorisationForAllK8sPermissions(token, clusterDescription.ClusterName, casbin.ActionUpdate)
	if !authenticated {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	// RBAC enforcer ends

	bean.IdentifierType = repository.ClusterType
	clusterNoteResponseBean, err := impl.clusterNoteService.Update(&bean, userId)

	if err != nil {
		impl.logger.Errorw("cluster note service err, Update", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, clusterNoteResponseBean, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) FindAllForAutoComplete(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clusterList, err := impl.clusterService.FindAllForAutoComplete()
	dbOperationTime := time.Since(start)
	if err != nil {
		impl.logger.Errorw("service err, FindAllForAutoComplete", "error", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	var result []bean2.ClusterBean
	v := r.URL.Query()
	authEnabled := true
	auth := v.Get("auth")
	if len(auth) > 0 {
		authEnabled, err = strconv.ParseBool(auth)
		if err != nil {
			authEnabled = true
			err = nil
			//ignore error, apply rbac by default
		}
	}
	// RBAC enforcer applying
	token := r.Header.Get("token")
	start = time.Now()
	for _, item := range clusterList {
		if authEnabled == true {
			if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionGet, item.ClusterName); ok {
				result = append(result, item)
			}
		} else {
			result = append(result, item)
		}

	}
	impl.logger.Infow("Cluster elapsed Time for enforcer", "dbElapsedTime", dbOperationTime, "enforcerTime", time.Since(start), "envSize", len(result))
	//RBAC enforcer Ends

	if len(result) == 0 {
		result = make([]bean2.ClusterBean, 0)
	}
	common.WriteJsonResp(w, err, result, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) DeleteCluster(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("service err, Delete", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	var bean bean2.DeleteClusterBean
	err = decoder.Decode(&bean)
	if err != nil {
		impl.logger.Errorw("request err, Delete", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}
	impl.logger.Debugw("request payload, Delete", "payload", bean)
	err = impl.validator.Struct(bean)
	if err != nil {
		impl.logger.Errorw("validate err, Delete", "error", err, "payload", bean)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	// RBAC enforcer applying
	token := r.Header.Get("token")
	if ok := impl.enforcer.Enforce(token, casbin.ResourceCluster, casbin.ActionCreate, "*"); !ok {
		common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
		return
	}
	//RBAC enforcer Ends
	err = impl.deleteService.DeleteCluster(&bean, userId)
	if err != nil {
		impl.logger.Errorw("error in deleting cluster", "err", err, "id", bean.Id)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, err, CLUSTER_DELETE_SUCCESS_RESP, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) GetAllClusterNamespaces(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("token")
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("err, GetAllClusterNamespaces", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	clusterNamespaces := impl.clusterService.GetAllClusterNamespaces()

	// RBAC enforcer applying
	filteredClusterNamespaces, err := impl.HandleRbacForClusterNamespace(userId, token, clusterNamespaces)
	if err != nil {
		impl.logger.Errorw("error in GetAllClusterNamespaces", "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	//RBAC enforcer Ends

	common.WriteJsonResp(w, nil, filteredClusterNamespaces, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) HandleRbacForClusterNamespace(userId int32, token string, clusterNamespaces map[string][]string) (map[string][]string, error) {
	filteredClusterNamespaces := make(map[string][]string)
	if ok := impl.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionGet, "*"); ok {
		return clusterNamespaces, nil
	}
	roles, err := impl.clusterService.FetchRolesFromGroup(userId)
	if err != nil {
		impl.logger.Errorw("error on fetching user roles for cluster list", "err", err)
		return nil, err
	}

	clusterAndNameSpaceVsAllowedMap := make(map[string]bool, len(roles))
	clusterNameVsAllAllowedMap := make(map[string]bool, len(roles))
	for _, role := range roles {
		clusterAndNameSpaceVsAllowedMap[strings.ToLower(role.Cluster+"_"+role.Namespace)] = true
		if role.Namespace == "" {
			clusterNameVsAllAllowedMap[role.Cluster] = true
		} else {
			clusterNameVsAllAllowedMap[role.Cluster] = false
		}
	}

	for clusterName, allNamespaces := range clusterNamespaces {
		if val, exist := clusterNameVsAllAllowedMap[clusterName]; val {
			filteredClusterNamespaces[clusterName] = allNamespaces
		} else if exist {
			for _, namespace := range allNamespaces {
				if val2, exist2 := clusterAndNameSpaceVsAllowedMap[strings.ToLower(clusterName+"_"+namespace)]; exist2 && val2 {
					filteredClusterNamespaces[clusterName] = append(filteredClusterNamespaces[clusterName], namespace)
				}
			}
		}
	}
	return filteredClusterNamespaces, nil

}

func (impl ClusterRestHandlerImpl) GetClusterNamespaces(w http.ResponseWriter, r *http.Request) {
	//token := r.Header.Get("token")
	vars := mux.Vars(r)
	clusterIdString := vars["clusterId"]

	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("user not authorized", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	isActionUserSuperAdmin := false
	if ok := impl.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionGet, "*"); ok {
		isActionUserSuperAdmin = true
	}
	clusterId, err := strconv.Atoi(clusterIdString)
	if err != nil {
		impl.logger.Errorw("failed to extract clusterId from param", "error", err, "clusterId", clusterIdString)
		common.WriteJsonResp(w, err, nil, http.StatusBadRequest)
		return
	}

	allClusterNamespaces, err := impl.clusterService.FindAllNamespacesByUserIdAndClusterId(userId, clusterId, isActionUserSuperAdmin)
	if err != nil {
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	common.WriteJsonResp(w, nil, allClusterNamespaces, http.StatusOK)
}

func (impl ClusterRestHandlerImpl) FindAllForClusterPermission(w http.ResponseWriter, r *http.Request) {
	userId, err := impl.userService.GetLoggedInUser(r)
	if userId == 0 || err != nil {
		impl.logger.Errorw("user not authorized", "error", err, "userId", userId)
		common.WriteJsonResp(w, err, "Unauthorized User", http.StatusUnauthorized)
		return
	}
	token := r.Header.Get("token")
	isActionUserSuperAdmin := false
	if ok := impl.enforcer.Enforce(token, casbin.ResourceGlobal, casbin.ActionGet, "*"); ok {
		isActionUserSuperAdmin = true
	}
	clusterList, err := impl.clusterService.FindAllForClusterByUserId(userId, isActionUserSuperAdmin)
	if err != nil {
		impl.logger.Errorw("error in deleting cluster", "err", err)
		common.WriteJsonResp(w, err, nil, http.StatusInternalServerError)
		return
	}
	// RBAC enforcer applying
	// Already applied at service layer
	//RBAC enforcer Ends

	if len(clusterList) == 0 {
		// assumption is that if list is empty, then it can happen only in case of Unauthorized (but not sending Unauthorized for super-admin user)
		if isActionUserSuperAdmin {
			clusterList = make([]bean2.ClusterBean, 0)
		} else {
			common.WriteJsonResp(w, errors.New("unauthorized"), nil, http.StatusForbidden)
			return
		}
	}
	common.WriteJsonResp(w, err, clusterList, http.StatusOK)
}
