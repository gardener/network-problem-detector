/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/deploy"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/manager"

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
	log                       logrus.FieldLogger
	hasUpdates                atomic.Bool
	informerFactory           informers.SharedInformerFactory
	informerFactoryKubeSystem informers.SharedInformerFactory
	nodesInformer             informerscorev1.NodeInformer
	podsInformer              informerscorev1.PodInformer
	knownPodIPs               atomic.Value
}

func newNodePodController(log logrus.FieldLogger, clientset kubernetes.Interface, resyncPeriod time.Duration) *nodePodController {
	informerFactory := informers.NewSharedInformerFactory(clientset, resyncPeriod)
	informerFactoryKubeSystem := informers.NewSharedInformerFactoryWithOptions(clientset,
		resyncPeriod, informers.WithNamespace(common.NamespaceKubeSystem))
	c := &nodePodController{
		log:                       log,
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
	pods, err := c.podsInformer.Lister().List(labels.SelectorFromSet(map[string]string{common.LabelKeyK8sApp: common.NameDaemonSetAgentPodNet}))

	// remember known pods
	podIPs := map[string]string{}
	for _, pod := range pods {
		if pod.Status.Phase == corev1.PodRunning {
			podIPs[pod.Name] = pod.Status.PodIP
		}
	}
	c.knownPodIPs.Store(podIPs)

	return pods, err
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
		if node, ok := obj.(*corev1.Node); ok {
			if node.CreationTimestamp.Add(1 * time.Minute).After(time.Now()) {
				c.log.WithField("node", node.Name).Info("node created")
			}
		}
		c.hasUpdates.Store(true)
	}
}

func (c *nodePodController) OnUpdate(oldObj, newObj interface{}) {
	if c.isRelevant(newObj) {
		if newPod, ok := newObj.(*corev1.Pod); ok {
			if newPod.Status.Phase == corev1.PodRunning {
				podIPs := c.knownPodIPs.Load().(map[string]string)
				if podIPs[newPod.Name] != newPod.Status.PodIP {
					// either new, yet unknown running agent pod or in very rare edge cases the PodIP has changed (e.g. after node reboot)
					c.hasUpdates.Store(true)
				}
			}
		}
	}
}

func (c *nodePodController) OnDelete(obj interface{}) {
	if c.isRelevant(obj) {
		if node, ok := obj.(*corev1.Node); ok {
			c.log.WithField("node", node.Name).Info("node deleted")
		}
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

type watch struct {
	log       logrus.FieldLogger
	clientSet *kubernetes.Clientset

	started  atomic.Bool
	lastLoop atomic.Int64
}

var _ manager.Runnable = &watch{}
var _ manager.LeaderElectionRunnable = &watch{}

func (w *watch) NeedLeaderElection() bool {
	return true
}

func (w *watch) healthzCheck(req *http.Request) error {
	if w.started.Load() && time.Now().UnixMilli()-w.lastLoop.Load() > 30000 {
		return fmt.Errorf("no successful loop since %s", time.UnixMilli(w.lastLoop.Load()))
	}
	return nil
}

func (w *watch) Start(ctx context.Context) error {
	w.lastLoop.Store(time.Now().UnixMilli())
	w.started.Store(true)

	controller := newNodePodController(w.log, w.clientSet, 24*time.Hour)
	stopCh := make(chan struct{})
	defer close(stopCh)
	if err := controller.Start(stopCh); err != nil {
		return err
	}

	var last time.Time
	for {
		select {
		case <-ctx.Done():
			stopCh <- struct{}{}
			return fmt.Errorf("stopped")
		default:
			now := time.Now()
			if delta := now.Sub(last); delta < 10*time.Second {
				time.Sleep(delta)
				continue
			}
			last = now
		}

		if !controller.HasUpdates() {
			w.lastLoop.Store(last.UnixMilli())
			continue
		}
		nodes, err := controller.ListNodes()
		if err != nil {
			w.log.Errorf("listing nodes failed: %s", err)
			continue
		}
		pods, err := controller.ListAgentPods()
		if err != nil {
			w.log.Errorf("listing pods ins namespace %s failed: %s", common.NamespaceKubeSystem, err)
			continue
		}

		svc, err := w.clientSet.CoreV1().Services(common.NamespaceDefault).Get(ctx, common.NameKubernetesService, metav1.GetOptions{})
		if err != nil {
			w.log.Errorf("loading service %s/%s failed: %s", common.NamespaceDefault, common.NameKubernetesService, err)
			continue
		}
		internalApiServer := &config.Endpoint{
			Hostname: common.DomainNameKubernetesService,
			IP:       svc.Spec.ClusterIP,
			Port:     int(svc.Spec.Ports[0].Port),
		}
		var apiServer *config.Endpoint
		configmaps := w.clientSet.CoreV1().ConfigMaps(common.NamespaceKubeSystem)
		shootInfo, err := configmaps.Get(ctx, common.NameGardenerShootInfo, metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				w.log.Errorf("loading configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameGardenerShootInfo, err)
				continue
			}
		}
		if err == nil {
			apiServer, err = deploy.GetAPIServerEndpointFromShootInfo(shootInfo)
			if err != nil {
				w.log.Errorf("fetching kube-apiserver external endpoint failed: %s", err)
				continue
			}
		}

		cm, err := configmaps.Get(ctx, common.NameClusterConfigMap, metav1.GetOptions{})
		if err != nil {
			w.log.Errorf("loading configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		content := cm.Data[common.ClusterConfigFilename]
		cfg := &config.ClusterConfig{}
		if err := yaml.Unmarshal([]byte(content), cfg); err != nil {
			w.log.Errorf("unmarshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		cfg, err = deploy.BuildClusterConfig(nodes, pods, internalApiServer, apiServer)
		cfgBytes, err := yaml.Marshal(cfg)
		if err != nil {
			w.log.Errorf("marshal configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
			continue
		}
		newContent := string(cfgBytes)
		cm.Data[common.ClusterConfigFilename] = newContent
		if newContent != content {
			if _, err := configmaps.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				w.log.Errorf("updating configmap %s/%s failed: %s", common.NamespaceKubeSystem, common.NameClusterConfigMap, err)
				continue
			}
			w.log.Infof("updated configmap %s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap)
			w.lastLoop.Store(last.UnixMilli())
		} else {
			w.log.Info("unchanged")
			w.lastLoop.Store(last.UnixMilli())
		}
	}
}
