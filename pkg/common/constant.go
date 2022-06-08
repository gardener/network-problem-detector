// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package common

const (
	// 	MDNSServiceHostNetAgent is the mDNS service name of the agent running on the host network.
	MDNSServiceHostNetAgent = "network-problem-detector-host-node._tcp"
	// NamespaceDefault is the default namespace
	NamespaceDefault = "default"
	// NamespaceKubeSystem is the kube-system namespace
	NamespaceKubeSystem = "kube-system"
	// NameKubernetes is the kubernetes service name
	NameKubernetes = "kubernetes"
	// NameGardenerShootInfo is the name of the shoot info config map from Gardener
	NameGardenerShootInfo = "shoot-info"
	// AgentConfigFilename is the name of the config file
	AgentConfigFilename = "agent-config.yaml"
	// ClusterConfigFilename is the name of the config file
	ClusterConfigFilename = "cluster-config.yaml"
	// EnvNodeName is the env variable to get the node name in an agent pod
	EnvNodeName = "NODE_NAME"
	// EnvNodeIP is the env variable to get the node ip in an agent pod
	EnvNodeIP = "NODE_IP"
	// EnvPodIP is the env variable to get the pod ip in an agent pod
	EnvPodIP = "POD_IP"
	// LabelKeyK8sApp is the label key used to mark the pods
	LabelKeyK8sApp = "k8s-app"
	// ApplicationName is the application name
	ApplicationName = "network-problem-detector"
	// NameAgentConfigMap name of the config map for the agents
	NameAgentConfigMap = ApplicationName + "-config"
	// NameClusterConfigMap name of the config map for the agents containing current nodes and agent pods
	NameClusterConfigMap = ApplicationName + "-cluster-config"
	// NameDaemonSetAgentHostNet name of the daemon set running in the host network
	NameDaemonSetAgentHostNet = ApplicationName + "-host"
	// NameDaemonSetAgentPodNet name of the daemon set running in the pod network
	NameDaemonSetAgentPodNet = ApplicationName + "-pod"
	// NameDeploymentAgentController name of the deployment running the agent controller
	NameDeploymentAgentController = ApplicationName + "-controller"
	// PathLogDir directory for logs on host file system
	PathLogDir = "/var/log/nwpd"
	// PathOutputDir path of output directory with observations in pods
	PathOutputDir = PathLogDir + "/records"
	// MaxLogfileSize is the maximum size of a log file written to the host file system
	MaxLogfileSize = 10 * 1000 * 1000
	// PodNetPodGRPCPort is the port used for the GRPC server of the pods running in the pod network
	PodNetPodGRPCPort = 8880
	// PodNetPodHttpPort is the port used for the metrics http server of the pods running in the pod network
	PodNetPodHttpPort = 8881
	// HostNetPodGRPCPort is the port used for the GRPC server of the pods running in the host network
	HostNetPodGRPCPort = 1011
	// HostNetPodHttpPort is the port used for the metrics http server of the pods running in the host network
	HostNetPodHttpPort = 1012
)
