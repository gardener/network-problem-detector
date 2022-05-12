// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	informerscorev1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

type nodePodController struct {
	hasUpdates                atomic.Bool
	informerFactory           informers.SharedInformerFactory
	informerFactoryKubeSystem informers.SharedInformerFactory
	nodesInformer             informerscorev1.NodeInformer
	podsInformer              informerscorev1.PodInformer
}

func newNodePodController(clientset kubernetes.Interface, resyncPeriod time.Duration) *nodePodController {
	informerFactory := informers.NewSharedInformerFactory(clientset, resyncPeriod)
	informerFactoryKubeSystem := informers.NewSharedInformerFactoryWithOptions(clientset,
		resyncPeriod, informers.WithNamespace(common.NamespaceKubeSystem))
	c := &nodePodController{
		informerFactory:           informerFactory,
		informerFactoryKubeSystem: informerFactoryKubeSystem,
		nodesInformer:             informerFactory.Core().V1().Nodes(),
		podsInformer:              informerFactoryKubeSystem.Core().V1().Pods(),
	}

	c.nodesInformer.Informer().AddEventHandler(c)
	c.podsInformer.Informer().AddEventHandler(c)

	return c
}

func (c *nodePodController) HasUpdates() bool {
	return c.hasUpdates.Swap(false)
}

func (c *nodePodController) ListNodes() ([]*corev1.Node, error) {
	return c.nodesInformer.Lister().List(labels.Everything())
}

func (c *nodePodController) ListAgentPods() ([]*corev1.Pod, error) {
	return c.podsInformer.Lister().List(labels.SelectorFromSet(map[string]string{common.LabelKeyK8sApp: common.NameDaemonSetAgentPodNet}))
}

func (c *nodePodController) Start(stopCh chan struct{}) error {
	c.informerFactory.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.nodesInformer.Informer().HasSynced) {
		return fmt.Errorf("Failed to sync")
	}

	c.informerFactoryKubeSystem.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.podsInformer.Informer().HasSynced) {
		return fmt.Errorf("Failed to sync")
	}

	return nil
}

func (c *nodePodController) OnAdd(obj interface{}) {
	if c.isRelevant(obj) {
		c.hasUpdates.Store(true)
	}
}

func (c *nodePodController) OnUpdate(oldObj, newObj interface{}) {
}

func (c *nodePodController) OnDelete(obj interface{}) {
	if c.isRelevant(obj) {
		c.hasUpdates.Store(true)
	}
}

func (c *nodePodController) isRelevant(obj interface{}) bool {
	if _, ok := obj.(*corev1.Node); ok {
		return ok
	}
	if pod, ok := obj.(*corev1.Pod); ok {
		labels := pod.GetLabels()
		return labels != nil && labels[common.LabelKeyK8sApp] == common.NameDaemonSetAgentPodNet
	}
	return false
}

func (dc *deployCommand) watch(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "deploy-watch")

	if err := dc.setupClientSet(); err != nil {
		return err
	}

	controller := newNodePodController(dc.clientset, 24*time.Hour)
	stopCh := make(chan struct{})
	defer close(stopCh)
	if err := controller.Start(stopCh); err != nil {
		return err
	}

	ctx := context.Background()
	var last time.Time
	for {
		now := time.Now()
		if now.Sub(last) < 30*time.Second {
			time.Sleep(now.Sub(last))
		}
		last = now
		if !controller.HasUpdates() {
			continue
		}
		nodes, err := controller.ListNodes()
		if err != nil {
			log.Errorf("listing nodes failed: %s", err)
			continue
		}
		pods, err := controller.ListAgentPods()
		if err != nil {
			log.Errorf("listing pods ins namespace %s failed: %s", common.NamespaceKubeSystem, err)
			continue
		}

		configmaps := dc.clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem)
		cm, err := configmaps.Get(ctx, common.NameAgentConfigMap, metav1.GetOptions{})
		if err != nil {
			log.Errorf("loading configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameAgentConfigMap, err)
			continue
		}
		content := cm.Data[common.AgentConfigFilename]
		cfg := &config.AgentConfig{}
		if err := yaml.Unmarshal([]byte(content), cfg); err != nil {
			log.Errorf("unmarshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameAgentConfigMap, err)
			continue
		}
		cfg.ClusterConfig, err = dc.buildClusterConfig(nodes, pods)
		cfgBytes, err := yaml.Marshal(cfg)
		if err != nil {
			log.Errorf("marshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameAgentConfigMap, err)
			continue
		}
		cm.Data[common.AgentConfigFilename] = string(cfgBytes)
		if _, err := configmaps.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			log.Errorf("updating configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameAgentConfigMap, err)
			continue
		}
		log.Infof("updated configmap %s/%s", common.NamespaceKubeSystem, common.NameAgentConfigMap)
	}

	return nil
}
