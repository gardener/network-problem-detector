// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/yaml"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
)

// defaultRepository is the default repository of the image used for deployment
//
//go:embed DEFAULT_REPOSITORY
var defaultRepository string

// AgentDeployConfig contains configuration for deploying the nwpd agent daemonset
type AgentDeployConfig struct {
	// Image is the image of the network problem detector agent to deploy
	Image string
	// DefaultPeriod is the default period for jobs
	DefaultPeriod time.Duration
	// DefaultSeccompProfileEnabled if seccomp profile should be defaulted to RuntimeDefault for the daemonsets
	DefaultSeccompProfileEnabled bool
	// PingEnabled if ping checks are enabled (needs NET_ADMIN capabilities)
	PingEnabled bool
	// PodSecurityPolicyEnabled if psp should be deployed
	PodSecurityPolicyEnabled bool
	// IgnoreAPIServerEndpoint if the check of the API server endpoint should be ignored
	IgnoreAPIServerEndpoint bool
	// PriorityClassName is the priority class name used for the daemon sets
	PriorityClassName string
	// K8sExporterEnabled if node conditions and events should be updated/created
	K8sExporterEnabled bool
	// K8sExporterHeartbeat if K8sExporterEnabled sets the period of updating the node condition `ClusterNetworkProblems` or `HostNetworkProblems`
	K8sExporterHeartbeat time.Duration
	// AdditionalAnnotations adds annotations to the daemonset spec template
	AdditionalAnnotations map[string]string
	// AdditionalLabels adds labels to the daemonset spec template
	AdditionalLabels map[string]string
	// DisableAutomountServiceAccountTokenForAgents controls if automountServiceAccountToken should always be false for agents as it is provided
	// by other means (e.g. https://github.com/gardener/gardener/blob/eb8400a2961400a8b984252a76eb546ea44432fd/docs/concepts/resource-manager.md#auto-mounting-projected-serviceaccount-tokens)
	DisableAutomountServiceAccountTokenForAgents bool
}

// DeployNetworkProblemDetectorAgent returns K8s resources to be created.
func DeployNetworkProblemDetectorAgent(config *AgentDeployConfig) ([]Object, error) {
	var objects []Object
	serviceAccountName, secObjects, err := config.buildSecurityObjects()
	if err != nil {
		return nil, err
	}
	if secObjects != nil {
		objects = append(objects, secObjects...)
	}
	for _, hostnetwork := range []bool{false, true} {
		svc, err := config.buildService(hostnetwork)
		if err != nil {
			return nil, err
		}
		objects = append(objects, svc)
		ds, err := config.buildDaemonSet(serviceAccountName, hostnetwork)
		if err != nil {
			return nil, err
		}
		objects = append(objects, ds)
	}

	return objects, nil
}

func (ac *AgentDeployConfig) AddImageFlag(imageTag string, flags *pflag.FlagSet) {
	defaultImage := defaultRepository + ":" + imageTag
	flags.StringVar(&ac.Image, "image", strings.TrimSpace(defaultImage), "the nwpd container image to use.")
}

func (ac *AgentDeployConfig) AddOptionFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&ac.DefaultPeriod, "default-period", 10*time.Second, "default period for jobs")
	flags.BoolVar(&ac.DefaultSeccompProfileEnabled, "default-seccomp-profile", false, "if seccomp profile should be defaulted to RuntimeDefault for network-problem-detector pods")
	flags.BoolVar(&ac.PingEnabled, "enable-ping", false, "if ICMP pings should be used in addition to TCP connection checks")
	flags.BoolVar(&ac.PodSecurityPolicyEnabled, "enable-psp", true, "if pod security policy should be deployed")
	flags.BoolVar(&ac.K8sExporterEnabled, "enable-k8s-exporter", false, "if node conditions and events should be updated/created")
	flags.DurationVar(&ac.K8sExporterHeartbeat, "k8s-exporter-heartbeat", 3*time.Minute, "period for updating the node conditions by the K8s exporter")
	flags.BoolVar(&ac.IgnoreAPIServerEndpoint, "ignore-gardener-kube-api-server", false, "if true, does not try to lookup kube api-server of Gardener control plane")
	flags.StringVar(&ac.PriorityClassName, "priority-class", "", "priority class name")
}

func (ac *AgentDeployConfig) buildService(hostnetwork bool) (*corev1.Service, error) {
	name, _ := ac.getNetworkConfig(hostnetwork)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.NamespaceKubeSystem,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
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

func (ac *AgentDeployConfig) getNetworkConfig(hostnetwork bool) (name string, portHttp int32) {
	if hostnetwork {
		name = common.NameDaemonSetAgentHostNet
		portHttp = common.HostNetPodHttpPort
	} else {
		name = common.NameDaemonSetAgentPodNet
		portHttp = common.PodNetPodHttpPort
	}
	return
}

func (ac *AgentDeployConfig) buildDaemonSet(serviceAccountName string, hostNetwork bool) (*appsv1.DaemonSet, error) {
	var (
		requestCPU, _          = resource.ParseQuantity("10m")
		limitCPU, _            = resource.ParseQuantity("50m")
		requestMemory, _       = resource.ParseQuantity("32Mi")
		limitMemory, _         = resource.ParseQuantity("64Mi")
		defaultMode      int32 = 0444
	)
	name, portHttp := ac.getNetworkConfig(hostNetwork)

	labels := ac.getLabels(name)
	labelsPlusAdditionalLabels := common.MergeMaps(ac.AdditionalLabels, labels)
	annotations := common.MergeMaps(ac.AdditionalAnnotations, map[string]string{"check-sum/k8s-exporter": strconv.FormatBool(ac.K8sExporterEnabled)})

	var capabilities *corev1.Capabilities
	if ac.PingEnabled {
		capabilities = &corev1.Capabilities{
			Add: []corev1.Capability{"NET_ADMIN"},
		}
	}
	var automountServiceAccountToken *bool
	if !ac.DisableAutomountServiceAccountTokenForAgents {
		automountServiceAccountToken = pointer.Bool(ac.K8sExporterEnabled)
	}

	typ := corev1.HostPathDirectoryOrCreate
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: common.NamespaceKubeSystem,
		},
		Spec: appsv1.DaemonSetSpec{
			RevisionHistoryLimit: pointer.Int32(5),
			Selector:             &metav1.LabelSelector{MatchLabels: labels},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.String, StrVal: "100%"},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labelsPlusAdditionalLabels,
					Annotations: annotations,
				},
				Spec: corev1.PodSpec{
					HostNetwork:                   hostNetwork,
					PriorityClassName:             ac.PriorityClassName,
					TerminationGracePeriodSeconds: pointer.Int64(0),
					Tolerations: []corev1.Toleration{
						{
							Effect:   corev1.TaintEffectNoSchedule,
							Operator: corev1.TolerationOpExists,
						},
						/*
							{
								Key:      "CriticalAddonsOnly",
								Operator: corev1.TolerationOpExists,
							},
						*/
						{
							Effect:   corev1.TaintEffectNoExecute,
							Operator: corev1.TolerationOpExists,
						},
					},
					AutomountServiceAccountToken: automountServiceAccountToken,
					ServiceAccountName:           serviceAccountName,
					Containers: []corev1.Container{{
						Name:            name,
						Image:           ac.Image,
						ImagePullPolicy: imagePullPolicyByImage(ac.Image),
						Command: []string{
							"/nwpdcli",
							"run-agent",
							fmt.Sprintf("--hostNetwork=%t", hostNetwork),
							"--config=/config/agent/" + common.AgentConfigFilename,
							"--cluster-config=/config/cluster/" + common.ClusterConfigFilename,
						},
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
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								TCPSocket: &corev1.TCPSocketAction{
									Port: intstr.FromInt(int(portHttp)),
								},
							},
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "metrics",
								ContainerPort: portHttp,
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
								Name:      "log",
								ReadOnly:  false,
								MountPath: common.PathLogDir,
							},
							{
								Name:      "agent-config",
								ReadOnly:  true,
								MountPath: "/config/agent",
							},
							{
								Name:      "cluster-config",
								ReadOnly:  true,
								MountPath: "/config/cluster",
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
							Name: "log",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: common.PathLogDir,
									Type: &typ,
								},
							},
						},
						{
							Name: "agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: common.NameAgentConfigMap},
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
						{
							Name: "cluster-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: common.NameClusterConfigMap},
									Items: []corev1.KeyToPath{
										{
											Key:  common.ClusterConfigFilename,
											Path: common.ClusterConfigFilename,
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

	if ac.DefaultSeccompProfileEnabled {
		if ds.Spec.Template.Spec.SecurityContext == nil {
			ds.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{}
		}

		ds.Spec.Template.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}
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
			RevisionHistoryLimit: pointer.Int32(5),
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
					PriorityClassName:             ac.PriorityClassName,
					TerminationGracePeriodSeconds: pointer.Int64(0),
					AutomountServiceAccountToken:  pointer.Bool(true),
					ServiceAccountName:            serviceAccountName,
					Containers: []corev1.Container{{
						Name:            name,
						Image:           ac.Image,
						ImagePullPolicy: imagePullPolicyByImage(ac.Image),
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
						SecurityContext: &corev1.SecurityContext{
							RunAsUser:  pointer.Int64(65534),
							RunAsGroup: pointer.Int64(65534),
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
			{
				APIGroups:     []string{""},
				Verbs:         []string{"get"},
				Resources:     []string{"services"},
				ResourceNames: []string{common.NameKubernetesService},
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
				ResourceNames: []string{common.NameAgentConfigMap, common.NameClusterConfigMap},
			},
			{
				APIGroups: []string{""},
				Verbs:     []string{"create"},
				Resources: []string{"configmaps"},
			},
			{
				APIGroups:     []string{""},
				Verbs:         []string{"get"},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{common.NameGardenerShootInfo},
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

func (ac *AgentDeployConfig) buildK8sExporterClusterRoleRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"nodes"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes/status"},
			Verbs:     []string{"patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch", "update"},
		},
	}
}

func (ac *AgentDeployConfig) buildSecurityObjects() (serviceAccountName string, objects []Object, retErr error) {
	if ac.PodSecurityPolicyEnabled {
		serviceAccountName = common.ApplicationName
		cr, crb, sa, psp, err := ac.buildPodSecurityPolicy(serviceAccountName)
		retErr = err
		objects = append(objects, cr, crb, sa, psp)
	} else if ac.K8sExporterEnabled {
		serviceAccountName = common.ApplicationName
		cr, crb, sa, err := ac.buildK8sExporterClusterRole(serviceAccountName)
		retErr = err
		objects = append(objects, cr, crb, sa)
	}
	return
}

func (ac *AgentDeployConfig) buildK8sExporterClusterRole(serviceAccountName string) (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, error) {
	roleName := "gardener.cloud:kube-system:" + common.ApplicationName
	rules := ac.buildK8sExporterClusterRoleRules()
	return ac.createClusterRuleAndServiceAccount(serviceAccountName, roleName, rules)
}

func (ac *AgentDeployConfig) createClusterRuleAndServiceAccount(serviceAccountName, roleName string, rules []rbacv1.PolicyRule) (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, error) {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: rules,
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
		AutomountServiceAccountToken: pointer.Bool(false),
	}

	return clusterRole, clusterRoleBinding, serviceAccount, nil
}

func (ac *AgentDeployConfig) buildPodSecurityPolicy(serviceAccountName string) (*rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *corev1.ServiceAccount, *policyv1beta1.PodSecurityPolicy, error) {
	roleName := "gardener.cloud:psp:kube-system:" + common.ApplicationName
	resourceName := "gardener.kube-system." + common.ApplicationName
	rules := []rbacv1.PolicyRule{
		{
			APIGroups:       []string{"policy"},
			Verbs:           []string{"use"},
			Resources:       []string{"podsecuritypolicies"},
			ResourceNames:   []string{resourceName},
			NonResourceURLs: nil,
		},
	}
	if ac.K8sExporterEnabled {
		rules = append(rules, ac.buildK8sExporterClusterRoleRules()...)
	}
	cr, crb, sa, err := ac.createClusterRuleAndServiceAccount(serviceAccountName, roleName, rules)
	if err != nil {
		return cr, crb, sa, nil, err
	}

	var allowedCapabilities []corev1.Capability
	if ac.PingEnabled {
		allowedCapabilities = []corev1.Capability{"NET_ADMIN"}
	}
	psp := &policyv1beta1.PodSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"seccomp.security.alpha.kubernetes.io/defaultProfileName":  "runtime/default",
				"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "runtime/default",
			},
			Name: resourceName,
		},
		Spec: policyv1beta1.PodSecurityPolicySpec{
			Privileged:               false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: nil,
			AllowedCapabilities:      allowedCapabilities,
			Volumes:                  []policyv1beta1.FSType{policyv1beta1.Secret, policyv1beta1.ConfigMap, policyv1beta1.HostPath},
			HostNetwork:              true,
			HostPorts: []policyv1beta1.HostPortRange{
				{Min: common.HostNetPodHttpPort, Max: common.HostNetPodHttpPort},
			},
			HostPID: false,
			HostIPC: false,
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
				{PathPrefix: common.PathLogDir, ReadOnly: false},
			},
		},
	}

	return cr, crb, sa, psp, nil
}

func (ac *AgentDeployConfig) BuildAgentConfig() (*config.AgentConfig, error) {
	cfg := config.AgentConfig{
		OutputDir:       common.PathOutputDir,
		RetentionHours:  4,
		LogObservations: false,
		HostNetwork: &config.NetworkConfig{
			DataFilePrefix: common.NameDaemonSetAgentHostNet,
			HttpPort:       common.HostNetPodHttpPort,
			DefaultPeriod:  metav1.Duration{Duration: ac.DefaultPeriod},
			Jobs: []config.Job{
				{
					JobID: "tcp-n2api-int",
					Args:  []string{"checkTCPPort", "--endpoint-internal-kube-apiserver", "--scale-period"},
				},
				{
					JobID: "tcp-n2n",
					Args:  []string{"checkTCPPort", "--node-port", fmt.Sprintf("%d", common.HostNetPodHttpPort)},
				},
				{
					JobID: "tcp-n2p",
					Args:  []string{"checkTCPPort", "--endpoints-of-pod-ds"},
				},
				{
					JobID: "nslookup-n",
					Args:  []string{"nslookup", "--names", "eu.gcr.io.", "--period", "1m"},
				},
			},
		},
		PodNetwork: &config.NetworkConfig{
			DataFilePrefix: common.NameDaemonSetAgentPodNet,
			DefaultPeriod:  metav1.Duration{Duration: ac.DefaultPeriod},
			HttpPort:       common.PodNetPodHttpPort,
			Jobs: []config.Job{
				{
					JobID: "tcp-p2api-int",
					Args:  []string{"checkTCPPort", "--endpoint-internal-kube-apiserver", "--scale-period"},
				},
				{
					JobID: "https-p2api-int",
					Args:  []string{"checkHTTPSGet", "--endpoint-internal-kube-apiserver", "--period", "1m", "--scale-period"},
				},
				{
					JobID: "tcp-p2n",
					Args:  []string{"checkTCPPort", "--node-port", fmt.Sprintf("%d", common.HostNetPodHttpPort)},
				},
				{
					JobID: "tcp-p2p",
					Args:  []string{"checkTCPPort", "--endpoints-of-pod-ds"},
				},
				{
					JobID: "nslookup-p",
					Args:  []string{"nslookup", "--names", "eu.gcr.io.", "--name-internal-kube-apiserver", "--period", "1m"},
				},
			},
		},
	}

	if ac.K8sExporterEnabled {
		cfg.K8sExporter = &config.K8sExporterConfig{
			Enabled:         true,
			HeartbeatPeriod: &metav1.Duration{Duration: ac.K8sExporterHeartbeat},
		}
	}

	if !ac.IgnoreAPIServerEndpoint {
		for i := range cfg.HostNetwork.Jobs {
			job := &cfg.HostNetwork.Jobs[i]
			if job.JobID == "nslookup-n" {
				job.Args = append(job.Args, "--name-external-kube-apiserver")
				break
			}
		}
		for i := range cfg.PodNetwork.Jobs {
			job := &cfg.PodNetwork.Jobs[i]
			if job.JobID == "nslookup-p" {
				job.Args = append(job.Args, "--name-external-kube-apiserver")
				break
			}
		}
		cfg.HostNetwork.Jobs = append(cfg.HostNetwork.Jobs,
			config.Job{
				JobID: "tcp-n2api-ext",
				Args:  []string{"checkTCPPort", "--endpoint-external-kube-apiserver", "--scale-period"},
			},
			config.Job{
				JobID: "https-n2api-ext",
				Args:  []string{"checkHTTPSGet", "--endpoint-external-kube-apiserver", "--period", "1m", "--scale-period"},
			})
		cfg.PodNetwork.Jobs = append(cfg.PodNetwork.Jobs,
			config.Job{
				JobID: "tcp-p2api-ext",
				Args:  []string{"checkTCPPort", "--endpoint-external-kube-apiserver", "--scale-period"},
			},
			config.Job{
				JobID: "https-p2api-ext",
				Args:  []string{"checkHTTPSGet", "--endpoint-external-kube-apiserver", "--period", "1m", "--scale-period"},
			})
	}
	if ac.PingEnabled {
		cfg.HostNetwork.Jobs = append(cfg.HostNetwork.Jobs,
			config.Job{
				JobID: "ping-n2n",
				Args:  []string{"pingHost"},
			})
		cfg.PodNetwork.Jobs = append(cfg.PodNetwork.Jobs,
			config.Job{
				JobID: "ping-p2n",
				Args:  []string{"pingHost"},
			})
	}

	return &cfg, nil
}

func BuildAgentConfigMap(agentConfig *config.AgentConfig) (*corev1.ConfigMap, error) {
	cfgBytes, err := yaml.Marshal(agentConfig)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.NameAgentConfigMap,
			Namespace: common.NamespaceKubeSystem,
		},
		Data: map[string]string{
			common.AgentConfigFilename: string(cfgBytes),
		},
	}
	return cm, nil
}

func BuildClusterConfigMap(clusterConfig *config.ClusterConfig) (*corev1.ConfigMap, error) {
	cfgBytes, err := yaml.Marshal(clusterConfig)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.NameClusterConfigMap,
			Namespace: common.NamespaceKubeSystem,
		},
		Data: map[string]string{
			common.ClusterConfigFilename: string(cfgBytes),
		},
	}
	return cm, nil
}

func imagePullPolicyByImage(image string) corev1.PullPolicy {
	if strings.HasSuffix(image, "-dev") || strings.HasSuffix(image, ":latest") {
		return corev1.PullAlways
	}
	return corev1.PullIfNotPresent
}
