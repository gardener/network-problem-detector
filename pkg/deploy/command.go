// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
)

type deployCommand struct {
	common.ClientsetBase
	delete            bool
	agentDeployConfig AgentDeployConfig
}

func CreateDeployCmd(imageTag string) *cobra.Command {
	dc := &deployCommand{}
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "deploy nwpd daemonsets and deployments",
		Long:  `deploy agent daemon sets and controller deployment`,
	}
	dc.AddKubeConfigFlag(cmd.PersistentFlags())
	dc.agentDeployConfig.AddImageFlag(imageTag, cmd.PersistentFlags())
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
	controllerCmd.Flags().StringVar(&dc.agentDeployConfig.PriorityClassName, "priority-class", "", "priority class name")

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
	return nil
}

func (dc *deployCommand) printDefaultConfig(cmd *cobra.Command, args []string) error {
	err := dc.setup()
	if err != nil {
		return err
	}

	cfg, err := dc.agentDeployConfig.BuildAgentConfig()
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
	err := dc.deployAgent(log, false, dc.buildAgentConfigMap, dc.buildClusterConfigMap)
	if err != nil {
		return err
	}
	return dc.deployAgent(log, true, dc.buildAgentConfigMap, dc.buildClusterConfigMap)
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
		if strings.HasSuffix(dc.agentDeployConfig.Image, "-dev") {
			log.Warnf("A dev image is used and may not be up-to-date or not existing. Consider to use the '--image' option to specify an image.")
		}

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

func (dc *deployCommand) deployAgent(log logrus.FieldLogger, hostnetwork bool,
	buildAgentConfigMap, buildClusterConfigMap buildObject[*corev1.ConfigMap]) error {
	ac := dc.agentDeployConfig
	name, _ := ac.getNetworkConfig(hostnetwork)

	err := dc.setup()
	if err != nil {
		return err
	}

	if dc.delete {
		return dc.deleteDaemonSet(log, name)
	}

	svc, err := ac.buildService(hostnetwork)
	if err != nil {
		return fmt.Errorf("error building service[%t]: %s", hostnetwork, err)
	}
	acm, err := buildAgentConfigMap()
	if err != nil {
		return fmt.Errorf("error building config map: %s", err)
	}
	ccm, err := buildClusterConfigMap()
	if err != nil {
		return fmt.Errorf("error building config map: %s", err)
	}

	serviceAccountName := ""
	var objects []Object
	serviceAccountName, objects, err = dc.agentDeployConfig.buildSecurityObjects()
	if err != nil {
		return err
	}

	ds, err := ac.buildDaemonSet(serviceAccountName, hostnetwork)
	if err != nil {
		return fmt.Errorf("error building daemon set: %s", err)
	}
	objects = append(objects, svc, acm, ccm, ds)
	ctx := context.Background()
	for _, obj := range objects {
		_, err = genericCreateOrUpdate(ctx, dc.Clientset, obj)
		if err != nil {
			return err
		}
	}

	if strings.HasSuffix(dc.agentDeployConfig.Image, "-dev") {
		log.Warnf("A dev image is used and may not be up-to-date or not existing. Consider to use the '--image' option to specify an image.")
	}
	log.Infof("deployed daemonset %s/%s", ds.Namespace, ds.Name)
	return nil
}

func (dc *deployCommand) deleteDaemonSet(log logrus.FieldLogger, name string) error {
	ctx := context.Background()
	err1 := dc.Clientset.AppsV1().DaemonSets(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err1 == nil {
		log.Infof("daemonset %s/%s deleted", common.NamespaceKubeSystem, name)
	}
	err2 := dc.Clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Delete(ctx, common.NameAgentConfigMap, metav1.DeleteOptions{})
	if err2 == nil {
		log.Infof("configmap %s/%s deleted", common.NamespaceKubeSystem, common.NameAgentConfigMap)
	}
	err3 := dc.Clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Delete(ctx, common.NameClusterConfigMap, metav1.DeleteOptions{})
	if err3 == nil {
		log.Infof("configmap %s/%s deleted", common.NamespaceKubeSystem, common.NameClusterConfigMap)
	}
	err4 := dc.Clientset.CoreV1().Services(common.NamespaceKubeSystem).Delete(ctx, name, metav1.DeleteOptions{})
	if err4 == nil {
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
	if err4 != nil && !errors.IsNotFound(err4) {
		return err4
	}

	return dc.deletePodSecurityPolicy(log)
}

func (dc *deployCommand) deletePodSecurityPolicy(log logrus.FieldLogger) error {
	ctx := context.Background()
	_, objects, err := dc.agentDeployConfig.buildSecurityObjects()
	if err != nil {
		return err
	}
	for _, obj := range objects {
		if err := genericDeleteWithLog(ctx, log, dc.Clientset, obj); err != nil {
			return err
		}
	}
	return nil
}

func (dc *deployCommand) buildAgentConfigMap() (*corev1.ConfigMap, error) {
	agentConfig, err := dc.agentDeployConfig.BuildAgentConfig()
	if err != nil {
		return nil, err
	}
	return BuildAgentConfigMap(agentConfig)
}

func (dc *deployCommand) buildClusterConfigMap() (*corev1.ConfigMap, error) {
	ctx := context.Background()
	svc, err := dc.Clientset.CoreV1().Services(common.NamespaceDefault).Get(ctx, common.NameKubernetesService, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	internalApiServer := &config.Endpoint{
		Hostname: common.DomainNameKubernetesService,
		IP:       svc.Spec.ClusterIP,
		Port:     int(svc.Spec.Ports[0].Port),
	}
	var apiServer *config.Endpoint
	if !dc.agentDeployConfig.IgnoreAPIServerEndpoint {
		shootInfo, err := dc.Clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Get(ctx, common.NameGardenerShootInfo, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error getting configmap %s/%s", common.NamespaceKubeSystem, common.NameGardenerShootInfo)
		}
		apiServer, err = GetAPIServerEndpointFromShootInfo(shootInfo)
		if err != nil {
			return nil, err
		}
	}
	nodes, err := dc.nodes()
	if err != nil {
		return nil, err
	}
	agentPods, err := dc.agentPods()
	if err != nil {
		return nil, err
	}

	clusterConfig, err := BuildClusterConfig(nodes, agentPods, internalApiServer, apiServer)
	if err != nil {
		return nil, err
	}
	return BuildClusterConfigMap(clusterConfig)
}

func (dc *deployCommand) nodes() ([]*corev1.Node, error) {
	ctx := context.Background()
	nodeList, err := dc.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing nodes: %w", err)
	}
	if nodeList == nil {
		return nil, nil
	}
	var nodes []*corev1.Node
	for _, n := range nodeList.Items {
		item := n
		nodes = append(nodes, &item)
	}
	return nodes, nil
}

func (dc *deployCommand) agentPods() ([]*corev1.Pod, error) {
	ctx := context.Background()
	podList, err := dc.Clientset.CoreV1().Pods(common.NamespaceKubeSystem).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", common.LabelKeyK8sApp, common.NameDaemonSetAgentPodNet),
	})
	if err != nil {
		return nil, fmt.Errorf("error listing pods: %w", err)
	}

	if podList == nil {
		return nil, nil
	}
	var pods []*corev1.Pod
	for _, p := range podList.Items {
		item := p
		pods = append(pods, &item)
	}
	return pods, nil
}
