// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
)

var defaultImage = "eu.gcr.io/gardener-project/test/network-problem-detector:v0.1.0-dev-220513e"

type deployCommand struct {
	common.ClientsetBase
	delete            bool
	agentDeployConfig AgentDeployConfig
	nodeList          *corev1.NodeList
	podList           *corev1.PodList
}

func CreateDeployCmd() *cobra.Command {
	dc := &deployCommand{}
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "deploy nwpd daemonsets and deployments",
		Long:  `deploy agent daemon sets and controller deployment`,
	}
	dc.AddKubeConfigFlag(cmd.PersistentFlags())
	dc.agentDeployConfig.AddImageFlag(cmd.PersistentFlags())
	dc.agentDeployConfig.AddOptionFlags(cmd.PersistentFlags())

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

	cmd.AddCommand(agentCmd)
	cmd.AddCommand(controllerCmd)
	cmd.AddCommand(printConfigCmd)
	return cmd
}

func (dc *deployCommand) setup() error {
	if err := dc.SetupClientSet(); err != nil {
		return err
	}
	if !dc.delete {
		if err := dc.setupNodeAndPodLists(); err != nil {
			return err
		}
	}
	return nil
}

func (dc *deployCommand) setupNodeAndPodLists() error {
	var err error
	ctx := context.Background()
	dc.nodeList, err = dc.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error listing nodes", err)
	}
	dc.podList, err = dc.Clientset.CoreV1().Pods(common.NamespaceKubeSystem).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", common.LabelKeyK8sApp, common.NameDaemonSetAgentPodNet),
	})
	if err != nil {
		return fmt.Errorf("error listing pods", err)
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

	ac := dc.agentDeployConfig
	ctx := context.Background()
	deployment, cr, crb, role, rolebinding, sa, err := ac.buildControllerDeployment()
	if err != nil {
		return err
	}
	for _, obj := range []Object{deployment, cr, crb, role, rolebinding, sa} {
		if !dc.delete {
			_, err = genericCreateOrUpdate(ctx, dc.Clientset, obj)
		} else {
			err = genericDeleteWithLog(ctx, log, dc.Clientset, obj)
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
	if err := dc.Clientset.AppsV1().Deployments(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return err
	}
	log.Infof("daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	return nil
}

func (dc *deployCommand) deployAgent(log logrus.FieldLogger, hostnetwork bool, buildConfigMap buildObject[*corev1.ConfigMap]) error {
	ac := dc.agentDeployConfig
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
			_, err = genericCreateOrUpdate(ctx, dc.Clientset, obj)
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
		_, err = genericCreateOrUpdate(ctx, dc.Clientset, obj)
		if err != nil {
			return err
		}
	}

	log.Infof("deployed daemonset %s/%s", ds.Namespace, ds.Name)
	return nil
}

func (dc *deployCommand) deleteDaemonSet(log logrus.FieldLogger, name, configMapName string) error {
	ctx := context.Background()
	err1 := dc.Clientset.AppsV1().DaemonSets(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err1 == nil {
		log.Infof("daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	}
	err2 := dc.Clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Delete(ctx, configMapName, metav1.DeleteOptions{})
	if err2 == nil {
		log.Infof("configmap %s/%s deleted", common.NamespaceKubeSystem, configMapName)
	}
	err3 := dc.Clientset.CoreV1().Services(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
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

	return dc.deletePodSecurityPolicy(log)
}

func (dc *deployCommand) deletePodSecurityPolicy(log logrus.FieldLogger) error {
	ctx := context.Background()
	serviceAccountName := common.ApplicationName
	cr, crb, sa, psp, err := dc.agentDeployConfig.buildPodSecurityPolicy(serviceAccountName)
	if err != nil {
		return err
	}
	for _, obj := range []Object{cr, crb, sa, psp} {
		if err := genericDeleteWithLog(ctx, log, dc.Clientset, obj); err != nil {
			return err
		}
	}
	return nil
}

func (dc *deployCommand) buildDefaultConfig() (*config.AgentConfig, error) {
	clusterConfig, err := dc.buildClusterConfig(dc.nodes(), dc.agentPods())
	if err != nil {
		return nil, err
	}

	apiServer, err := dc.agentDeployConfig.GetAPIServerEndpointFromShootInfo(dc.Clientset)
	if err != nil {
		return nil, err
	}

	return dc.agentDeployConfig.BuildDefaultConfig(clusterConfig, apiServer)
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
	return BuildAgentConfigMap(cfg)
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
