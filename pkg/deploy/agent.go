// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"

	"github.com/gardener/network-problem-detector/pkg/common"
)

// AgentDeployConfig contains configuration for deploying the nwpd agent daemonset
type AgentDeployConfig struct {
	// Image is the image of the network problem detector agent to deploy
	Image string
	// DefaultPeriod is the default period for jobs
	DefaultPeriod time.Duration
	// PingEnabled if ping checks are enabled (needs NET_ADMIN capabilities)
	PingEnabled bool
	// PodSecurityPolicyEnabled if psp should be deployed
	PodSecurityPolicyEnabled bool
}

// DeployNetworkProblemDetectorAgent returns K8s resources to be created.
func DeployNetworkProblemDetectorAgent(config *AgentDeployConfig) ([]Object, error) {
	var objects []Object
	serviceAccountName := ""
	if config.PodSecurityPolicyEnabled {
		serviceAccountName = common.ApplicationName
		cr, crb, sa, psp, err := config.buildPodSecurityPolicy(serviceAccountName)
		if err != nil {
			return nil, err
		}
		objects = append(objects, cr, crb, sa, psp)
	}
	for _, hostnetwork := range []bool{false, true} {
		svc, err := config.buildService(hostnetwork)
		if err != nil {
			return nil, err
		}
		objects = append(objects, svc)
		ds, err := config.buildDaemonSet(common.NameAgentConfigMap, serviceAccountName, hostnetwork)
		if err != nil {
			return nil, err
		}
		objects = append(objects, ds)
	}

	return objects, nil
}

func (ac *AgentDeployConfig) buildService(hostnetwork bool) (*corev1.Service, error) {
	name, _, _ := ac.getNetworkConfig(hostnetwork)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.NamespaceKubeSystem,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:     "grpc",
					Protocol: corev1.ProtocolTCP,
					Port:     80,
					TargetPort: intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "grpc",
					},
				},
				{
					Name:     "metrics",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
					TargetPort: intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "metrics",
					},
				},
			},
			Selector: ac.getLabels(name),
			Type:     corev1.ServiceTypeClusterIP,
		},
	}
	return svc, nil
}

func (ac *AgentDeployConfig) getLabels(name string) map[string]string {
	return map[string]string{
		common.LabelKeyK8sApp: name,
		"gardener.cloud/role": "network-problem-detector",
	}
}

func (ac *AgentDeployConfig) getNetworkConfig(hostnetwork bool) (name string, portGRPC, portMetrics int32) {
	if hostnetwork {
		name = common.NameDaemonSetAgentNodeNet
		portGRPC = common.NodeNetPodGRPCPort
		portMetrics = common.NodeNetPodHttpPort
	} else {
		name = common.NameDaemonSetAgentPodNet
		portGRPC = common.PodNetPodGRPCPort
		portMetrics = common.PodNetPodHttpPort
	}
	return
}

func (ac *AgentDeployConfig) buildDaemonSet(nameConfigMap, serviceAccountName string, hostNetwork bool) (*appsv1.DaemonSet, error) {
	var (
		requestCPU, _          = resource.ParseQuantity("10m")
		limitCPU, _            = resource.ParseQuantity("50m")
		requestMemory, _       = resource.ParseQuantity("32Mi")
		limitMemory, _         = resource.ParseQuantity("64Mi")
		defaultMode      int32 = 0444
	)
	name, portGRPC, portMetrics := ac.getNetworkConfig(hostNetwork)

	labels := ac.getLabels(name)

	var capabilities *corev1.Capabilities
	if ac.PingEnabled {
		capabilities = &corev1.Capabilities{
			Add: []corev1.Capability{"NET_ADMIN"},
		}
	}

	typ := corev1.HostPathDirectoryOrCreate
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.NamespaceKubeSystem,
		},
		Spec: appsv1.DaemonSetSpec{
			RevisionHistoryLimit: pointer.Int32Ptr(5),
			Selector:             &metav1.LabelSelector{MatchLabels: labels},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.String, StrVal: "100%"},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					HostNetwork: hostNetwork,
					//PriorityClassName:             "system-node-critical",
					TerminationGracePeriodSeconds: pointer.Int64(0),
					/*
						Tolerations: []corev1.Toleration{
							{
								Effect:   corev1.TaintEffectNoSchedule,
								Operator: corev1.TolerationOpExists,
							},
							{
								Key:      "CriticalAddonsOnly",
								Operator: corev1.TolerationOpExists,
							},
							{
								Effect:   corev1.TaintEffectNoExecute,
								Operator: corev1.TolerationOpExists,
							},
						},
					*/
					AutomountServiceAccountToken: pointer.Bool(false),
					ServiceAccountName:           serviceAccountName,
					Containers: []corev1.Container{{
						Name:            name,
						Image:           ac.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/nwpdcli", "run-agent", fmt.Sprintf("--hostNetwork=%t", hostNetwork), "--config", "/config/" + common.AgentConfigFilename},
						Env: []corev1.EnvVar{
							{
								Name: common.EnvNodeName,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name: common.EnvNodeIP,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.hostIP",
									},
								},
							},
							{
								Name: common.EnvPodIP,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "status.podIP",
									},
								},
							},
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "grpc",
								ContainerPort: portGRPC,
								Protocol:      "TCP",
							},
							{
								Name:          "metrics",
								ContainerPort: portMetrics,
								Protocol:      "TCP",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    requestCPU,
								corev1.ResourceMemory: requestMemory,
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    limitCPU,
								corev1.ResourceMemory: limitMemory,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Capabilities: capabilities,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "output",
								ReadOnly:  false,
								MountPath: common.PathOutputDir,
							},
							{
								Name:      "config",
								ReadOnly:  true,
								MountPath: "/config",
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "output",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: common.PathOutputDir,
									Type: &typ,
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: nameConfigMap},
									Items: []corev1.KeyToPath{
										{
											Key:  common.AgentConfigFilename,
											Path: common.AgentConfigFilename,
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
		},
	}

	return ds, nil
}

func (ac *AgentDeployConfig) buildControllerDeployment() (*appsv1.Deployment, *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding,
	*rbacv1.Role, *rbacv1.RoleBinding, *corev1.ServiceAccount, error) {
	var (
		requestCPU, _    = resource.ParseQuantity("10m")
		limitCPU, _      = resource.ParseQuantity("50m")
		requestMemory, _ = resource.ParseQuantity("32Mi")
		limitMemory, _   = resource.ParseQuantity("128Mi")
	)

	name := common.NameDeploymentAgentController
	labels := ac.getLabels(name)
	serviceAccountName := name

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.NamespaceKubeSystem,
		},
		Spec: appsv1.DeploymentSpec{
			RevisionHistoryLimit: pointer.Int32Ptr(5),
			Selector:             &metav1.LabelSelector{MatchLabels: labels},
			Replicas:             pointer.Int32(1),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					//PriorityClassName:             "system-node-critical",
					TerminationGracePeriodSeconds: pointer.Int64(0),
					/*
						Tolerations: []corev1.Toleration{
							{
								Effect:   corev1.TaintEffectNoSchedule,
								Operator: corev1.TolerationOpExists,
							},
							{
								Key:      "CriticalAddonsOnly",
								Operator: corev1.TolerationOpExists,
							},
							{
								Effect:   corev1.TaintEffectNoExecute,
								Operator: corev1.TolerationOpExists,
							},
						},
					*/
					AutomountServiceAccountToken: pointer.Bool(true),
					ServiceAccountName:           serviceAccountName,
					Containers: []corev1.Container{{
						Name:            name,
						Image:           ac.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/nwpdcli", "run-controller", "--in-cluster"},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    requestCPU,
								corev1.ResourceMemory: requestMemory,
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    limitCPU,
								corev1.ResourceMemory: limitMemory,
							},
						},
					}},
				},
			},
		},
	}

	roleName := "gardener.cloud:" + name
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"get", "list", "watch"},
				Resources: []string{"nodes"},
			},
		},
	}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: common.NamespaceKubeSystem,
			},
		},
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: common.NamespaceKubeSystem,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs:     []string{"get", "list", "watch"},
				Resources: []string{"pods"},
			},
			{
				APIGroups:     []string{""},
				Verbs:         []string{"get", "update", "patch"},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{common.NameAgentConfigMap},
			},
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
		},
	}
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: common.NamespaceKubeSystem,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: common.NamespaceKubeSystem,
			},
		},
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: common.NamespaceKubeSystem,
		},
		AutomountServiceAccountToken: pointer.Bool(false),
	}

	return deployment, clusterRole, clusterRoleBinding, role, roleBinding, serviceAccount, nil
}

// TODO test and fine-tuning
func (ac *AgentDeployConfig) buildPodSecurityPolicy(serviceAccountName string) (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, *policyv1beta1.PodSecurityPolicy, error) {
	roleName := "gardener.cloud:psp:kube-system:" + common.ApplicationName
	resourceName := "gardener.kube-system." + common.ApplicationName
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:       []string{"policy"},
				Verbs:           []string{"use"},
				Resources:       []string{"podsecuritypolicies"},
				ResourceNames:   []string{resourceName},
				NonResourceURLs: nil,
			},
		},
	}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: common.NamespaceKubeSystem,
			},
		},
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: common.NamespaceKubeSystem,
		},
	}
	var allowedCapabilities []corev1.Capability
	if ac.PingEnabled {
		allowedCapabilities = []corev1.Capability{"NET_ADMIN"}
	}
	psp := &policyv1beta1.PodSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceName,
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: nil,
			AllowedCapabilities:      allowedCapabilities,
			Volumes:                  []policyv1beta1.FSType{policyv1beta1.Secret, policyv1beta1.ConfigMap},
			HostNetwork:              true,
			HostPorts:                nil,
			HostPID:                  false,
			HostIPC:                  false,
			SELinux: policyv1beta1.SELinuxStrategyOptions{
				Rule: policyv1beta1.SELinuxStrategyRunAsAny,
			},
			RunAsUser: policyv1beta1.RunAsUserStrategyOptions{
				Rule: policyv1beta1.RunAsUserStrategyRunAsAny,
			},
			RunAsGroup: nil,
			SupplementalGroups: policyv1beta1.SupplementalGroupsStrategyOptions{
				Rule: policyv1beta1.SupplementalGroupsStrategyRunAsAny,
			},
			FSGroup: policyv1beta1.FSGroupStrategyOptions{
				Rule: policyv1beta1.FSGroupStrategyRunAsAny,
			},
			ReadOnlyRootFilesystem:          false,
			DefaultAllowPrivilegeEscalation: nil,
			AllowPrivilegeEscalation:        pointer.Bool(true),
			AllowedHostPaths: []policyv1beta1.AllowedHostPath{
				{PathPrefix: common.PathOutputBaseDir, ReadOnly: false},
			},
		},
	}

	return clusterRole, clusterRoleBinding, serviceAccount, psp, nil
}
