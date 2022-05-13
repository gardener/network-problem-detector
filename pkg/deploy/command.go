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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"sigs.k8s.io/yaml"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
)

var defaultImage = "eu.gcr.io/gardener-project/test/network-problem-detector:v0.1.0-dev-220513c"

type deployCommand struct {
	kubeconfig    string
	image         string
	delete        bool
	pingEnabled   bool
	pspEnabled    bool
	inCluster     bool
	defaultPeriod time.Duration
	clientset     *kubernetes.Clientset
	nodeList      *corev1.NodeList
	podList       *corev1.PodList
	apiServer     *config.Endpoint
}

func CreateDeployCmd() *cobra.Command {
	dc := &deployCommand{}
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "deploy nwpd daemonsets and deployments",
		Long:  `deploy agent daemon sets and controller deployment`,
	}
	cmd.PersistentFlags().StringVar(&dc.kubeconfig, "kubeconfig", "", "kubeconfig for shoot cluster, uses KUBECONFIG if not specified.")
	cmd.PersistentFlags().StringVar(&dc.image, "image", defaultImage, "the nwpd container image to use.")
	cmd.PersistentFlags().DurationVar(&dc.defaultPeriod, "default-period", 10*time.Second, "default period for jobs.")
	cmd.PersistentFlags().BoolVar(&dc.pingEnabled, "enable-ping", false, "if ICMP pings should be used in addition to TCP connection checks")
	cmd.PersistentFlags().BoolVar(&dc.pspEnabled, "enable-psp", false, "if pod security policy should be deployed")

	agentCmd := &cobra.Command{
		Use:     "agent",
		Aliases: []string{"a"},
		Short:   "deploy agent daemonsets",
		RunE:    dc.deployAgentAllDaemonsets,
	}
	agentCmd.Flags().BoolVar(&dc.delete, "delete", false, "if true, the daemonsets are deleted.")

	controllerCmd := &cobra.Command{
		Use:     "controller",
		Aliases: []string{"c", "ctrl"},
		Short:   "deploy controller for watching nodes and pods",
		RunE:    dc.deployAgentControllerDeployment,
	}
	controllerCmd.Flags().BoolVar(&dc.delete, "delete", false, "if true, the deployment is deleted.")

	printConfigCmd := &cobra.Command{
		Use:     "print-default-config",
		Aliases: []string{"print"},
		Short:   "prints default configuration for nwpd-agent daemon sets.",
		RunE:    dc.printDefaultConfig,
	}

	watchCmd := &cobra.Command{
		Use:   "run-controller",
		Short: "watch nodes and pods to adjust configmap",
		RunE:  dc.watch,
	}
	watchCmd.Flags().BoolVar(&dc.inCluster, "in-cluster", false, "if controller runs inside a pod")

	cmd.AddCommand(agentCmd)
	cmd.AddCommand(controllerCmd)
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
	var err error
	var config *rest.Config
	if dc.inCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("error on InClusterConfig: %s", err)
		}
	} else {
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
		config, err = clientcmd.BuildConfigFromFlags("", dc.kubeconfig)
		if err != nil {
			return fmt.Errorf("error on config from kubeconfig file %s: %s", dc.kubeconfig, err)
		}
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
	dc.apiServer = &config.Endpoint{
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
	log := logrus.WithField("cmd", "deploy-agent")
	err := dc.deployAgent(log, false, dc.buildCommonConfigMap)
	if err != nil {
		return err
	}
	return dc.deployAgent(log, true, dc.buildCommonConfigMap)
}

func (dc *deployCommand) deployAgentControllerDeployment(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "deploy-controller")

	err := dc.setup()
	if err != nil {
		return err
	}

	ac := dc.buildAgentDeployConfig()
	ctx := context.Background()
	deployment, cr, crb, role, rolebinding, sa, err := ac.buildControllerDeployment()
	if err != nil {
		return err
	}
	for _, obj := range []Object{deployment, cr, crb, role, rolebinding, sa} {
		if !dc.delete {
			_, err = genericCreateOrUpdate(ctx, dc.clientset, obj)
		} else {
			err = genericDeleteWithLog(ctx, log, dc.clientset, obj)
		}
		if err != nil {
			return err
		}
	}
	if !dc.delete {
		log.Infof("deployed deployment %s/%s", deployment.Namespace, deployment.Name)
	}
	return nil
}

func (dc *deployCommand) deleteAgentControllerDeployment(log logrus.FieldLogger) error {
	ctx := context.Background()
	name := common.NameDeploymentAgentController
	if err := dc.clientset.AppsV1().Deployments(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return err
	}
	log.Infof("daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	return nil
}

func (dc *deployCommand) buildAgentDeployConfig() *AgentDeployConfig {
	return &AgentDeployConfig{
		Image:                    dc.image,
		DefaultPeriod:            dc.defaultPeriod,
		PingEnabled:              dc.pingEnabled,
		PodSecurityPolicyEnabled: dc.pspEnabled,
	}
}

func (dc *deployCommand) deployAgent(log logrus.FieldLogger, hostnetwork bool, buildConfigMap buildObject[*corev1.ConfigMap]) error {
	ac := dc.buildAgentDeployConfig()
	name, _, _ := ac.getNetworkConfig(hostnetwork)

	err := dc.setup()
	if err != nil {
		return err
	}

	if dc.delete {
		return dc.deleteDaemonSet(log, name, common.NameAgentConfigMap)
	}

	svc, err := ac.buildService(hostnetwork)
	if err != nil {
		return fmt.Errorf("error building service[%t]: %s", hostnetwork, err)
	}
	cm, err := buildConfigMap()
	if err != nil {
		return fmt.Errorf("error building config map: %s", err)
	}

	ctx := context.Background()

	serviceAccountName := ""
	if ac.PodSecurityPolicyEnabled {
		serviceAccountName = common.ApplicationName
		cr, crb, sa, psp, err := ac.buildPodSecurityPolicy(serviceAccountName)
		if err != nil {
			return err
		}
		for _, obj := range []Object{cr, crb, sa, psp} {
			_, err = genericCreateOrUpdate(ctx, dc.clientset, obj)
			if err != nil {
				return err
			}
		}
	}

	ds, err := ac.buildDaemonSet(cm.GetName(), serviceAccountName, hostnetwork)
	if err != nil {
		return fmt.Errorf("error building daemon set: %s", err)
	}
	for _, obj := range []Object{svc, cm, ds} {
		_, err = genericCreateOrUpdate(ctx, dc.clientset, obj)
		if err != nil {
			return err
		}
	}

	log.Infof("deployed daemonset %s/%s", ds.Namespace, ds.Name)
	return nil
}

func (dc *deployCommand) deleteDaemonSet(log logrus.FieldLogger, name, configMapName string) error {
	ctx := context.Background()
	err1 := dc.clientset.AppsV1().DaemonSets(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err1 == nil {
		log.Infof("daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	}
	err2 := dc.clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Delete(ctx, configMapName, metav1.DeleteOptions{})
	if err2 == nil {
		log.Infof("configmap %s/%s deleted", common.NamespaceKubeSystem, configMapName)
	}
	err3 := dc.clientset.CoreV1().Services(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err3 == nil {
		log.Infof("service %s/%s deleted", common.NamespaceKubeSystem, name)
	}
	if err1 != nil && !errors.IsNotFound(err1) {
		return err1
	}
	if err2 != nil && !errors.IsNotFound(err2) {
		return err2
	}
	if err3 != nil && !errors.IsNotFound(err3) {
		return err3
	}

	if dc.pspEnabled {
		return dc.deletePodSecurityPolicy(log)
	}
	return nil
}

func (dc *deployCommand) deletePodSecurityPolicy(log logrus.FieldLogger) error {
	ac := dc.buildAgentDeployConfig()
	ctx := context.Background()
	serviceAccountName := common.ApplicationName
	cr, crb, sa, psp, err := ac.buildPodSecurityPolicy(serviceAccountName)
	if err != nil {
		return err
	}
	for _, obj := range []Object{cr, crb, sa, psp} {
		if err := genericDeleteWithLog(ctx, log, dc.clientset, obj); err != nil {
			return err
		}
	}
	return nil
}

func (dc *deployCommand) buildDefaultConfig() (*config.AgentConfig, error) {
	cfg := config.AgentConfig{
		OutputDir:         common.PathOutputDir,
		RetentionHours:    4,
		LogDroppingFactor: 0.9,
		NodeNetwork: &config.NetworkConfig{
			DataFilePrefix:  common.NameDaemonSetAgentNodeNet,
			Port:            common.NodeNetPodGRPCPort,
			StartMDNSServer: true,
			DefaultPeriod:   dc.defaultPeriod,
			Jobs: []config.Job{
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
		PodNetwork: &config.NetworkConfig{
			DataFilePrefix: common.NameDaemonSetAgentPodNet,
			DefaultPeriod:  dc.defaultPeriod,
			Port:           common.PodNetPodGRPCPort,
			Jobs: []config.Job{
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
	cfg.NodeNetwork.Jobs = append(cfg.NodeNetwork.Jobs, config.Job{
		JobID: "tcp-n2svc",
		Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("nwpd-agent-pod-net:%s:80", podNetServiceClusterIP)},
	})
	cfg.PodNetwork.Jobs = append(cfg.PodNetwork.Jobs, config.Job{
		JobID: "tcp-p2svc",
		Args:  []string{"checkTCPPort", "--endpoints", fmt.Sprintf("nwpd-agent-pod-net:%s:80", podNetServiceClusterIP)},
	})

	if dc.pingEnabled {
		cfg.NodeNetwork.Jobs = append(cfg.NodeNetwork.Jobs,
			config.Job{
				JobID: "ping-n2n",
				Args:  []string{"pingHost"},
			},
			config.Job{
				JobID: "ping-n2api-ext",
				Args:  []string{"pingHost", "--hosts", dc.apiServer.Hostname + ":" + dc.apiServer.IP},
			})
		cfg.PodNetwork.Jobs = append(cfg.NodeNetwork.Jobs,
			config.Job{
				JobID: "ping-p2n",
				Args:  []string{"pingHost"},
			},
			config.Job{
				JobID: "ping-p2api-ext",
				Args:  []string{"pingHost", "--hosts", dc.apiServer.Hostname + ":" + dc.apiServer.IP},
			})
	}

	cfg.ClusterConfig, err = dc.buildClusterConfig(dc.nodes(), dc.agentPods())
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (dc *deployCommand) buildClusterConfig(nodes []*corev1.Node, agentPods []*corev1.Pod) (config.ClusterConfig, error) {
	clusterConfig := config.ClusterConfig{}

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
			return clusterConfig, fmt.Errorf("invalid node: %s", n.Name)
		}
		clusterConfig.Nodes = append(clusterConfig.Nodes, config.Node{
			Hostname:   hostname,
			InternalIP: ip,
		})
	}

	for _, p := range agentPods {
		clusterConfig.PodEndpoints = append(clusterConfig.PodEndpoints, config.PodEndpoint{
			Nodename: p.Spec.NodeName,
			Podname:  p.Name,
			PodIP:    p.Status.PodIP,
			Port:     common.PodNetPodGRPCPort,
		})
	}

	return clusterConfig, nil
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
			Name:      common.NameAgentConfigMap,
			Namespace: common.NamespaceKubeSystem,
		},
		Data: map[string]string{
			common.AgentConfigFilename: string(cfgBytes),
		},
	}
	return cm, nil
}

func (dc *deployCommand) getPodNetServiceClusterIP() (string, error) {
	ctx := context.Background()
	svc, err := dc.clientset.CoreV1().Services(common.NamespaceKubeSystem).Get(ctx, common.NameDaemonSetAgentPodNet, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting service %s/%s: %s", "getting", common.NamespaceKubeSystem, common.NameDaemonSetAgentPodNet, err)
	}
	return svc.Spec.ClusterIP, nil
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
