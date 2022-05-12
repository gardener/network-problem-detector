// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
)

// AgentDeployConfig contains configuration for deploying the nwpd agent daemonset
type AgentDeployConfig struct {
	// Image is the image of the network problem detector agent to deploy
	Image string
	// DefaultPeriod is the default period for jobs
	DefaultPeriod time.Duration
}

func DeployNetworkProblemDetectorAgent(config *AgentDeployConfig) ([]Object, error) {
	var objects []Object
	for _, hostnetwork := range []bool{false, true} {
		svc, err := config.buildService(hostnetwork)
		if err != nil {
			return nil, err
		}
		objects = append(objects, svc)
		ds, err := config.buildDaemonSet(nameConfigMapAgentConfig, hostnetwork)
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
		portMetrics = common.NodeNetPodMetricsPort
	} else {
		name = common.NameDaemonSetAgentPodNet
		portGRPC = common.PodNetPodGRPCPort
		portMetrics = common.PodNetPodMetricsPort
	}
	return
}

func (ac *AgentDeployConfig) buildDaemonSet(nameConfigMap string, hostNetwork bool) (*appsv1.DaemonSet, error) {
	var (
		requestCPU, _          = resource.ParseQuantity("50m")
		limitCPU, _            = resource.ParseQuantity("500m")
		requestMemory, _       = resource.ParseQuantity("64Mi")
		limitMemory, _         = resource.ParseQuantity("256Mi")
		defaultMode      int32 = 0444
		zero             int64 = 0
	)
	name, portGRPC, portMetrics := ac.getNetworkConfig(hostNetwork)

	labels := ac.getLabels(name)

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
					TerminationGracePeriodSeconds: &zero,
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
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"NET_ADMIN"},
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "output",
								ReadOnly:  false,
								MountPath: outputDir,
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
									Path: outputDir,
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
