package bean

import (
	"fmt"
	"strconv"
	"strings"
)

type DeploymentConfig struct {
	Id                int
	AppId             int
	EnvironmentId     int
	ConfigType        string
	DeploymentAppType string
	RepoURL           string
	RepoName          string
	ReleaseMode       string
	Active            bool
}

type UniqueDeploymentConfigIdentifier string

type DeploymentConfigSelector struct {
	AppId         int
	EnvironmentId int
	CDPipelineId  int
}

func (u UniqueDeploymentConfigIdentifier) String() string {
	return string(u)
}

func GetConfigUniqueIdentifier(appId, envId int) UniqueDeploymentConfigIdentifier {
	return UniqueDeploymentConfigIdentifier(fmt.Sprintf("%d-%d", appId, envId))

}

func (u *UniqueDeploymentConfigIdentifier) GetAppAndEnvId() (appId, envId int) {
	splitArr := strings.Split(u.String(), "-")
	appIdStr, envIdStr := splitArr[0], splitArr[1]
	appId, _ = strconv.Atoi(appIdStr)
	envId, _ = strconv.Atoi(envIdStr)
	return appId, envId
}

type DeploymentConfigType string

const (
	CUSTOM           DeploymentConfigType = "custom"
	SYSTEM_GENERATED DeploymentConfigType = "system_generated"
)

func (d DeploymentConfigType) String() string {
	return string(d)
}

type DeploymentConfigCredentialType string

const (
	GitOps DeploymentConfigCredentialType = "gitOps"
)

func (d DeploymentConfigCredentialType) String() string {
	return string(d)
}

// DefaultStopTemplate default Stop template for system charts
const DefaultStopTemplate = `{"replicaCount":0,"autoscaling":{"MinReplicas":0,"MaxReplicas":0,"enabled":false},"kedaAutoscaling":{"minReplicaCount":0,"maxReplicaCount":0,"enabled":false},"secondaryWorkload":{"replicaCount":0,"autoscaling":{"enabled":false,"MinReplicas":0,"MaxReplicas":0}}}`
