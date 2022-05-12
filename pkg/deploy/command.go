// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/yaml"

	"github/gardener/network-problem-detector/pkg/agent"
	"github/gardener/network-problem-detector/pkg/common"
	"github/gardener/network-problem-detector/pkg/common/nwpd"
)

const (
	nameConfigMapAgentConfig = "nwpd-agent-config"
	outputDir                = common.PathOutputDir
)

var defaultImage = "eu.gcr.io/gardener-project/test/network-problem-detector/nwpdcli:v0.1.0-dev-220511a"

type deployCommand struct {
	kubeconfig    string
	image         string
	delete        bool
	defaultPeriod time.Duration
	clientset     *kubernetes.Clientset
	nodeList      *corev1.NodeList
	podList       *corev1.PodList
	apiServer     *nwpd.Endpoint
}

func CreateDeployCmd() *cobra.Command {
	dc := &deployCommand{}
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "deploy nwpd daemonsets and deployments",
		Long:  `deploy agent daemon sets (and leader?)`,
	}
	cmd.PersistentFlags().StringVar(&dc.kubeconfig, "kubeconfig", "", "kubeconfig for shoot cluster, uses KUBECONFIG if not specified.")
	cmd.PersistentFlags().StringVar(&dc.image, "image", defaultImage, "the nwpd container image to use.")
	cmd.PersistentFlags().BoolVar(&dc.delete, "delete", false, "if true, the deployment is deleted.")
	cmd.PersistentFlags().DurationVar(&dc.defaultPeriod, "default-period", 10*time.Second, "default period for jobs.")

	allCmd := &cobra.Command{
		Use:   "all",
		Short: "deploy all agent daemonsets",
		RunE:  dc.deployAgentAllDaemonsets,
	}

	printConfigCmd := &cobra.Command{
		Use:   "print-default-config",
		Short: "prints default configuration for nwpd-agent daemon sets.",
		RunE:  dc.printDefaultConfig,
	}

	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "watch nodes and pods to adjust configmap",
		RunE:  dc.watch,
	}

	cmd.AddCommand(allCmd)
	cmd.AddCommand(printConfigCmd)
	cmd.AddCommand(watchCmd)
	return cmd
}

func (dc *deployCommand) setup() error {
	if err := dc.setupClientSet(); err != nil {
		return err
	}
	if !dc.delete {
		if err := dc.setupShootInfo(); err != nil {
			return err
		}
	}
	return nil
}

func (dc *deployCommand) setupClientSet() error {
	if dc.kubeconfig == "" {
		dc.kubeconfig = os.Getenv("KUBECONFIG")
	}
	if dc.kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			dc.kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	if dc.kubeconfig == "" {
		return fmt.Errorf("cannot find kubeconfig: neither '--kubeconfig' option, env var 'KUBECONFIG', or file '$HOME/.kube/config' available")
	}
	config, err := clientcmd.BuildConfigFromFlags("", dc.kubeconfig)
	if err != nil {
		return fmt.Errorf("error on config from kubeconfig file %s: %s", dc.kubeconfig, err)
	}
	dc.clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating clientset: %s", err)
	}
	return nil
}

func (dc *deployCommand) setupShootInfo() error {
	var err error
	ctx := context.Background()
	dc.nodeList, err = dc.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing nodes", err)
	}
	dc.podList, err = dc.clientset.CoreV1().Pods(common.NamespaceKubeSystem).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", common.LabelKeyK8sApp, common.NameDaemonSetAgentPodNet),
	})
	if err != nil {
		return fmt.Errorf("error listing pods", err)
	}

	shootInfo, err := dc.clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Get(ctx, "shoot-info", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting configmap %s/shoot-info", common.NamespaceKubeSystem)
	}

	domain, ok := shootInfo.Data["domain"]
	if !ok {
		return fmt.Errorf("missing 'domain' key in configmap %s/shoot-info", common.NamespaceKubeSystem)
	}
	apiServer := "api." + domain
	ips, err := net.LookupIP(apiServer)
	if err != nil {
		return fmt.Errorf("error looking up shoot apiserver %s: %s", apiServer, err)
	}
	dc.apiServer = &nwpd.Endpoint{
		Hostname: apiServer,
		IP:       ips[0].String(),
		Port:     443,
	}
	return nil
}

func (dc *deployCommand) printDefaultConfig(cmd *cobra.Command, args []string) error {
	err := dc.setup()
	if err != nil {
		return err
	}

	cfg, err := dc.buildDefaultConfig()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return err
	}
	println(string(data))
	return nil
}

func (dc *deployCommand) deployAgentAllDaemonsets(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "deploy-all")
	err := dc.deployAgent(log, true, dc.buildCommonConfigMap)
	if err != nil {
		return err
	}
	return dc.deployAgent(log, false, dc.buildCommonConfigMap)
}

func (dc *deployCommand) deployAgent(log logrus.FieldLogger, hostnetwork bool, buildConfigMap buildObject[*corev1.ConfigMap]) error {
	name, _, _ := dc.getNetworkConfig(hostnetwork)

	err := dc.setup()
	if err != nil {
		return err
	}

	cm, err := buildConfigMap()
	if err != nil {
		return fmt.Errorf("error building config map: %s", err)
	}

	if dc.delete {
		return dc.deleteDaemonSet(log, name, cm.GetName())
	}

	ctx := context.Background()
	svc, err := dc.buildService(hostnetwork)
	if err != nil {
		return fmt.Errorf("error building service[%t]: %s", hostnetwork, err)
	}
	_, err = createOrUpdate(ctx, "service", dc.clientset.CoreV1().Services(common.NamespaceKubeSystem), svc)
	if err != nil {
		return err
	}

	_, err = createOrUpdate(ctx, "configmap", dc.clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem), cm)
	if err != nil {
		return err
	}

	ds, err := dc.buildDaemonSet(cm.GetName(), hostnetwork)
	if err != nil {
		return fmt.Errorf("error building daemon set: %s", err)
	}
	_, err = createOrUpdate(ctx, "daemonset", dc.clientset.AppsV1().DaemonSets(common.NamespaceKubeSystem), ds)
	if err != nil {
		return err
	}

	log.Infof("deployed daemonset %s/%s", ds.Namespace, ds.Name)
	return nil
}

func (dc *deployCommand) deleteDaemonSet(log logrus.FieldLogger, name, configMapName string) error {
	ctx := context.Background()
	err1 := dc.clientset.AppsV1().DaemonSets(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	err2 := dc.clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Delete(ctx, configMapName, metav1.DeleteOptions{})
	err3 := dc.clientset.CoreV1().Services(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err1 != nil && !errors.IsNotFound(err1) {
		return err1
	}
	if err2 != nil && !errors.IsNotFound(err2) {
		return err2
	}
	if err3 != nil && !errors.IsNotFound(err3) {
		return err3
	}
	log.Infof("deployed daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	return nil
}

func (dc *deployCommand) buildDefaultConfig() (*agent.Config, error) {
	cfg := agent.Config{
		OutputDir:         outputDir,
		RetentionHours:    4,
		LogDroppingFactor: 0.9,
		NodeNetwork: &agent.NetworkConfig{
			DataFilePrefix:  common.NameDaemonSetAgentNodeNet,
			Port:            common.NodeNetPodGRPCPort,
			StartMDNSServer: true,
			DefaultPeriod:   dc.defaultPeriod,
			Jobs: []nwpd.Job{
				{
					JobID: "ping-n2n",
					Args:  []string{"pingHost"},
				},
				{
					JobID: "ping-n2api-ext",
					Args:  []string{"pingHost", "--hosts", dc.apiServer.Hostname + ":" + dc.apiServer.IP},
				},
				{
					JobID: "tcp-n2api-ext",
					Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("%s:%s:%d", dc.apiServer.Hostname, dc.apiServer.IP, dc.apiServer.Port)},
				},
				{
					JobID: "tcp-n2kubeproxy",
					Args:  []string{"checkTCPPort", "--node-port", "10249"},
				},
				{
					JobID: "mdns-n2n",
					Args:  []string{"discoverMDNS", "--period", "1m"},
				},
				{
					JobID: "tcp-n2p",
					Args:  []string{"checkTCPPort", "--endpoints-of-pod-ds"},
				},
			},
		},
		PodNetwork: &agent.NetworkConfig{
			DataFilePrefix: common.NameDaemonSetAgentPodNet,
			DefaultPeriod:  dc.defaultPeriod,
			Port:           common.PodNetPodGRPCPort,
			Jobs: []nwpd.Job{
				{
					JobID: "ping-p2n",
					Args:  []string{"pingHost"},
				},
				{
					JobID: "ping-p2api-ext",
					Args:  []string{"pingHost", "--hosts", dc.apiServer.Hostname + ":" + dc.apiServer.IP},
				},
				{
					JobID: "tcp-p2api-ext",
					Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("%s:%s:%d", dc.apiServer.Hostname, dc.apiServer.IP, dc.apiServer.Port)},
				},
				{
					JobID: "tcp-p2api-int",
					Args:  []string{"checkTCPPort", "--endpoints", "kubernetes:100.64.0.1:443"},
				},
				{
					JobID: "tcp-p2kubeproxy",
					Args:  []string{"checkTCPPort", "--node-port", "10249"},
				},
				{
					JobID: "tcp-p2p",
					Args:  []string{"checkTCPPort", "--endpoints-of-pod-ds"},
				},
			},
		},
	}

	podNetServiceClusterIP, err := dc.getPodNetServiceClusterIP()
	if err != nil {
		return nil, err
	}
	cfg.NodeNetwork.Jobs = append(cfg.NodeNetwork.Jobs, nwpd.Job{
		JobID: "tcp-n2svc",
		Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("nwpd-agent-pod-net:%s:80", podNetServiceClusterIP)},
	})
	cfg.PodNetwork.Jobs = append(cfg.PodNetwork.Jobs, nwpd.Job{
		JobID: "tcp-p2svc",
		Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("nwpd-agent-pod-net:%s:80", podNetServiceClusterIP)},
	})

	cfg.ClusterConfig, err = dc.buildClusterConfig(dc.nodes(), dc.agentPods())
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (dc *deployCommand) buildClusterConfig(nodes []*corev1.Node, agentPods []*corev1.Pod) (nwpd.ClusterConfig, error) {
	config := nwpd.ClusterConfig{}

	for _, n := range nodes {
		hostname := ""
		ip := ""
		for _, addr := range n.Status.Addresses {
			switch addr.Type {
			case "Hostname":
				hostname = addr.Address
			case "InternalIP":
				ip = addr.Address
			}
		}
		if hostname == "" || ip == "" {
			return config, fmt.Errorf("invalid node: %s", n.Name)
		}
		config.Nodes = append(config.Nodes, nwpd.Node{
			Hostname:   hostname,
			InternalIP: ip,
		})
	}

	for _, p := range agentPods {
		config.PodEndpoints = append(config.PodEndpoints, nwpd.PodEndpoint{
			Nodename:  p.Spec.NodeName,
			Podname:   p.Name,
			ClusterIP: p.Status.PodIP,
			Port:      common.PodNetPodGRPCPort,
		})
	}

	return config, nil
}

func (dc *deployCommand) buildCommonConfigMap() (*corev1.ConfigMap, error) {
	cfg, err := dc.buildDefaultConfig()
	if err != nil {
		return nil, err
	}
	cfgBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nameConfigMapAgentConfig,
			Namespace: common.NamespaceKubeSystem,
		},
		Data: map[string]string{
			common.AgentConfigFilename: string(cfgBytes),
		},
	}
	return cm, nil
}

func (dc *deployCommand) getNetworkConfig(hostnetwork bool) (name string, portGRPC, portMetrics int32) {
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

func (dc *deployCommand) buildService(hostnetwork bool) (*corev1.Service, error) {
	name, _, _ := dc.getNetworkConfig(hostnetwork)
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
			Selector: dc.getLabels(name),
			Type:     corev1.ServiceTypeClusterIP,
		},
	}
	return svc, nil
}

func (dc *deployCommand) getPodNetServiceClusterIP() (string, error) {
	ctx := context.Background()
	svc, err := dc.clientset.CoreV1().Services(common.NamespaceKubeSystem).Get(ctx, common.NameDaemonSetAgentPodNet, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting service %s/%s: %s", "getting", common.NamespaceKubeSystem, common.NameDaemonSetAgentPodNet, err)
	}
	return svc.Spec.ClusterIP, nil
}

func (dc *deployCommand) getLabels(name string) map[string]string {
	return map[string]string{
		common.LabelKeyK8sApp: name,
		"gardener.cloud/role": "network-problem-detector",
	}
}

func (dc *deployCommand) buildDaemonSet(nameConfigMap string, hostNetwork bool) (*appsv1.DaemonSet, error) {
	var (
		requestCPU, _          = resource.ParseQuantity("50m")
		limitCPU, _            = resource.ParseQuantity("500m")
		requestMemory, _       = resource.ParseQuantity("64Mi")
		limitMemory, _         = resource.ParseQuantity("256Mi")
		defaultMode      int32 = 0444
		zero             int64 = 0
	)
	name, portGRPC, portMetrics := dc.getNetworkConfig(hostNetwork)

	labels := dc.getLabels(name)

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
						Image:           dc.image,
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

func (dc *deployCommand) nodes() []*corev1.Node {
	if dc.nodeList == nil {
		return nil
	}
	var nodes []*corev1.Node
	for _, n := range dc.nodeList.Items {
		item := n
		nodes = append(nodes, &item)
	}
	return nodes
}

func (dc *deployCommand) agentPods() []*corev1.Pod {
	if dc.podList == nil {
		return nil
	}
	var pods []*corev1.Pod
	for _, p := range dc.podList.Items {
		item := p
		pods = append(pods, &item)
	}
	return pods
}
