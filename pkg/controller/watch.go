/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/deploy"
	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/sirupsen/logrus"
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
	if oldPod, ok := oldObj.(*corev1.Pod); ok {
		if c.isRelevant(newObj) {
			if newPod, ok := newObj.(*corev1.Pod); ok {
				if oldPod.Status.Phase != corev1.PodRunning && newPod.Status.Phase == corev1.PodRunning {
					c.hasUpdates.Store(true)
				}
			}
		}
	}
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

func (cc *controllerCommand) watch(log logrus.FieldLogger) error {
	if err := cc.SetupClientSet(); err != nil {
		return err
	}

	controller := newNodePodController(cc.Clientset, 24*time.Hour)
	stopCh := make(chan struct{})
	defer close(stopCh)
	if err := controller.Start(stopCh); err != nil {
		return err
	}

	ctx := context.Background()
	var last time.Time
	for {
		now := time.Now()
		if delta := now.Sub(last); delta < 10*time.Second {
			time.Sleep(delta)
			continue
		}
		last = now
		if !controller.HasUpdates() {
			cc.lastLoop.Store(last.UnixMilli())
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

		svc, err := cc.Clientset.CoreV1().Services(common.NamespaceDefault).Get(ctx, common.NameKubernetes, metav1.GetOptions{})
		if err != nil {
			log.Errorf("loading service %s/%s failed: %s", common.NamespaceDefault, common.NameKubernetes, err)
			continue
		}
		internalApiServer := &config.Endpoint{
			Hostname: common.NameKubernetes,
			IP:       svc.Spec.ClusterIP,
			Port:     int(svc.Spec.Ports[0].Port),
		}
		var apiServer *config.Endpoint
		configmaps := cc.Clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem)
		shootInfo, err := configmaps.Get(ctx, common.NameGardenerShootInfo, metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Errorf("loading configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameGardenerShootInfo, err)
				continue
			}
		}
		if err == nil {
			apiServer, err = deploy.GetAPIServerEndpointFromShootInfo(shootInfo)
			if err != nil {
				log.Errorf("fetching kube-apiserver external endpoint failed: %s", err)
				continue
			}
		}

		cm, err := configmaps.Get(ctx, common.NameClusterConfigMap, metav1.GetOptions{})
		if err != nil {
			log.Errorf("loading configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		content := cm.Data[common.ClusterConfigFilename]
		cfg := &config.ClusterConfig{}
		if err := yaml.Unmarshal([]byte(content), cfg); err != nil {
			log.Errorf("unmarshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		cfg, err = deploy.BuildClusterConfig(nodes, pods, internalApiServer, apiServer)
		cfgBytes, err := yaml.Marshal(cfg)
		if err != nil {
			log.Errorf("marshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		newContent := string(cfgBytes)
		cm.Data[common.ClusterConfigFilename] = newContent
		if newContent != content {
			if _, err := configmaps.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				log.Errorf("updating configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
				continue
			}
			log.Infof("updated configmap %s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap)
			cc.lastLoop.Store(last.UnixMilli())
		} else {
			log.Info("unchanged")
			cc.lastLoop.Store(last.UnixMilli())
		}
	}
}
