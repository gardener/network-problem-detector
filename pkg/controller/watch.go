/*
 * SPDX-FileCopyrightText: Contributors to the Gardener project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package controller

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/deploy"

	"github.com/go-logr/logr"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	informerscorev1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/yaml"
)

type nodePodController struct {
	log                       logr.Logger
	hasUpdates                atomic.Bool
	informerFactory           informers.SharedInformerFactory
	informerFactoryKubeSystem informers.SharedInformerFactory
	nodesInformer             informerscorev1.NodeInformer
	podsInformer              informerscorev1.PodInformer
	knownPodIPs               atomic.Value
}

func newNodePodController(log logr.Logger, clientset kubernetes.Interface, resyncPeriod time.Duration) (*nodePodController, error) {
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

	if _, err := c.nodesInformer.Informer().AddEventHandler(c); err != nil {
		return nil, err
	}
	if _, err := c.podsInformer.Informer().AddEventHandler(c); err != nil {
		return nil, err
	}

	return c, nil
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
		return fmt.Errorf("failed to sync")
	}

	c.informerFactoryKubeSystem.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.podsInformer.Informer().HasSynced) {
		return fmt.Errorf("failed to sync")
	}

	return nil
}

func (c *nodePodController) OnAdd(obj any, _ bool) {
	if c.isRelevant(obj) {
		if node, ok := obj.(*corev1.Node); ok {
			if node.CreationTimestamp.Add(1 * time.Minute).After(time.Now()) {
				c.log.WithValues("node", node.Name).Info("node created")
			}
		}
		c.hasUpdates.Store(true)
	}
}

func (c *nodePodController) OnUpdate(_, newObj any) {
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

func (c *nodePodController) OnDelete(obj any) {
	if c.isRelevant(obj) {
		if node, ok := obj.(*corev1.Node); ok {
			c.log.WithValues("node", node.Name).Info("node deleted")
		}
		c.hasUpdates.Store(true)
	}
}

func (c *nodePodController) isRelevant(obj any) bool {
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
	log       logr.Logger
	clientSet kubernetes.Interface

	// clock and resolveAPIServer are optional; defaults are used if unset.
	clock            clock.WithTicker
	resolveAPIServer func(shootInfo *corev1.ConfigMap) (*config.Endpoint, error)

	started  atomic.Bool
	lastLoop atomic.Int64
}

const watchLoopInterval = 10 * time.Second

func (w *watch) getAPIServerEndpoint(shootInfo *corev1.ConfigMap) (*config.Endpoint, error) {
	if w.resolveAPIServer != nil {
		return w.resolveAPIServer(shootInfo)
	}
	return deploy.GetAPIServerEndpointFromShootInfo(shootInfo)
}

func (w *watch) getClock() clock.WithTicker {
	if w.clock != nil {
		return w.clock
	}
	return clock.RealClock{}
}

var (
	_ manager.Runnable               = &watch{}
	_ manager.LeaderElectionRunnable = &watch{}
)

func (w *watch) NeedLeaderElection() bool {
	return true
}

func (w *watch) healthzCheck(_ *http.Request) error {
	if w.started.Load() && w.getClock().Now().UnixMilli()-w.lastLoop.Load() > 30000 {
		return fmt.Errorf("no successful loop since %s", time.UnixMilli(w.lastLoop.Load()))
	}
	return nil
}

func (w *watch) Start(ctx context.Context) error {
	clk := w.getClock()
	w.lastLoop.Store(clk.Now().UnixMilli())
	w.started.Store(true)

	controller, err := newNodePodController(w.log, w.clientSet, 24*time.Hour)
	if err != nil {
		return err
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	if err := controller.Start(stopCh); err != nil {
		return err
	}

	ticker := clk.NewTicker(watchLoopInterval)
	defer ticker.Stop()

	var shootInfo *corev1.ConfigMap
	var apiServer *config.Endpoint
	var nodeCIDRs []net.IPNet
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				stopCh <- struct{}{}
				return fmt.Errorf("stopped")
			case <-ticker.C():
			}
		}
		last := clk.Now()

		if !controller.HasUpdates() && !w.apiServerAddressChanged(shootInfo, apiServer) {
			w.lastLoop.Store(last.UnixMilli())
			continue
		}
		nodes, err := controller.ListNodes()
		if err != nil {
			w.log.Error(err, "listing nodes failed")
			continue
		}
		pods, err := controller.ListAgentPods()
		if err != nil {
			w.log.Error(err, "listing pods failed", "namespace", common.NamespaceKubeSystem)
			continue
		}

		svc, err := w.clientSet.CoreV1().Services(common.NamespaceDefault).Get(ctx, common.NameKubernetesService, metav1.GetOptions{})
		if err != nil {
			w.log.Error(err, "loading service failed", "service", fmt.Sprintf("%s/%s", common.NamespaceDefault, common.NameKubernetesService))
			continue
		}
		internalAPIServer := &config.Endpoint{
			Hostname: common.DomainNameKubernetesService,
			IP:       svc.Spec.ClusterIP,
			Port:     int(svc.Spec.Ports[0].Port),
		}
		configmaps := w.clientSet.CoreV1().ConfigMaps(common.NamespaceKubeSystem)
		shootInfo, err = configmaps.Get(ctx, common.NameGardenerShootInfo, metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				w.log.Error(err, "loading configmap failed", "configmap", fmt.Sprintf("%s/%s", common.NamespaceKubeSystem, common.NameGardenerShootInfo))
				continue
			}
			// NOTE: client-go returns an empty object, even if the requested object does not exist.
			shootInfo = nil
		}
		if err == nil {
			apiServer, err = w.getAPIServerEndpoint(shootInfo)
			if err != nil {
				w.log.Error(err, "fetching kube-apiserver external endpoint failed")
				continue
			}
		}
		if err == nil {
			nodeCIDRs, err = deploy.GetNodeNetworksFromShootInfo(shootInfo)
			if err != nil {
				w.log.Error(err, "failed to get node networks from shoot-info")
				continue
			}
		}
		apiserverStr := "<none>"
		if apiServer != nil {
			apiserverStr = fmt.Sprintf("%s:%d", apiServer.Hostname, apiServer.Port)
		}
		w.log.Info("shoot info", "nodeCIDRs", nodeCIDRs, "apiserver", apiserverStr)

		cm, err := configmaps.Get(ctx, common.NameClusterConfigMap, metav1.GetOptions{})
		if err != nil {
			w.log.Error(err, "loading configmap failed", "configmap", fmt.Sprintf("%s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap))
			continue
		}
		content := cm.Data[common.ClusterConfigFilename]
		cfg, err := deploy.BuildClusterConfig(w.log, nodes, pods, internalAPIServer, apiServer, nodeCIDRs)
		if err != nil {
			w.log.Error(err, "building cluster config failed")
			continue
		}
		cfgBytes, err := yaml.Marshal(cfg)
		if err != nil {
			w.log.Error(err, "marshalling configmap failed", "configmap", fmt.Sprintf("%s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap))
			continue
		}
		newContent := string(cfgBytes)
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[common.ClusterConfigFilename] = newContent
		msg := "configmap unchanged"
		if newContent != content {
			if _, err := configmaps.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
				w.log.Error(err, "updating configmap failed", "configmap", fmt.Sprintf("%s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap))
				continue
			}
			msg = "configmap updated"
		}
		w.log.Info(msg, "configmap", fmt.Sprintf("%s/%s", common.NamespaceKubeSystem, common.NameClusterConfigMap))
		w.lastLoop.Store(last.UnixMilli())
	}
}

func (w *watch) apiServerAddressChanged(shootInfo *corev1.ConfigMap, apiServer *config.Endpoint) bool {
	if shootInfo == nil || apiServer == nil {
		return true
	}
	newAPIServer, err := w.getAPIServerEndpoint(shootInfo)
	if err != nil {
		w.log.Error(err, "failed to determine apiserver endpoint from shoot info")
		return true
	}
	return *newAPIServer != *apiServer
}
