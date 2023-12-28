/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// based on: https://github.com/kubernetes/node-problem-detector/blob/7fd465e195fc2a9e203775c9f24c9c445cf3d513/pkg/exporters/k8sexporter/problemclient/problem_client.go

package problemclient

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/clock"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

// Client is the interface of problem client.
type Client interface {
	// GetConditions get all specific conditions of current node.
	GetConditions(ctx context.Context, conditionTypes []corev1.NodeConditionType) ([]corev1.NodeCondition, error)
	// SetConditions set or update conditions of current node.
	SetConditions(ctx context.Context, conditions []corev1.NodeCondition) error
	// Eventf reports the event.
	Eventf(eventType string, source, reason, messageFmt string, args ...interface{})
	// GetNode returns the Node object of the node on which the
	// node-problem-detector runs.
	GetNode(ctx context.Context) (*corev1.Node, error)
}

type Options struct {
	// AgentName is the name of the agent used to communicate with Kubernetes ApiServer.
	AgentName string
	// AgentVersion is the version of the agent used to communicate with Kubernetes ApiServer.
	AgentVersion string
	// NodeName is the node name used to communicate with Kubernetes ApiServer.
	NodeName string
	// EventNamespace is the namespace events are written to
	EventNamespace string
	// KubeConfigPath allows to override in-cluster config
	KubeConfigPath string
	// Log is the logger
	Log logrus.FieldLogger
}

type networkProblemClient struct {
	log              logrus.FieldLogger
	nodeName         string
	client           typedcorev1.CoreV1Interface
	clock            clock.WithTicker
	recorders        map[string]record.EventRecorder
	nodeRef          *corev1.ObjectReference
	eventNamespace   string
	cachedConditions map[corev1.NodeConditionType]corev1.NodeCondition
}

// NewClient creates a new problem client.
func NewClient(options *Options) (Client, error) {
	c := &networkProblemClient{clock: clock.RealClock{}}

	cfg, err := clientcmd.BuildConfigFromFlags("", options.KubeConfigPath)
	if err != nil {
		return nil, err
	}

	cfg.UserAgent = fmt.Sprintf("%s/%s", options.AgentName, options.AgentVersion)
	// TODO(random-liu): Set QPS Limit
	c.log = options.Log
	cs, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	c.client = cs.CoreV1()
	c.nodeName = options.NodeName
	c.eventNamespace = options.EventNamespace
	c.nodeRef = getNodeRef(c.eventNamespace, c.nodeName)
	c.recorders = make(map[string]record.EventRecorder)
	c.cachedConditions = make(map[corev1.NodeConditionType]corev1.NodeCondition)
	return c, nil
}

func (c *networkProblemClient) GetConditions(ctx context.Context, conditionTypes []corev1.NodeConditionType) ([]corev1.NodeCondition, error) {
	if len(conditionTypes) == 0 {
		return nil, nil
	}
	node, err := c.GetNode(ctx)
	if err != nil {
		return nil, err
	}
	conditions := []corev1.NodeCondition{}
	for _, conditionType := range conditionTypes {
		for _, condition := range node.Status.Conditions {
			if condition.Type == conditionType {
				conditions = append(conditions, condition)
			}
		}
	}
	return conditions, nil
}

func (c *networkProblemClient) SetConditions(ctx context.Context, newConditions []corev1.NodeCondition) error {
	if len(newConditions) == 0 {
		return nil
	}
	if err := c.mergeConditionsLastTransitionTime(ctx, newConditions); err != nil {
		return err
	}
	for i := range newConditions {
		// Each time we update the conditions, we update the heart beat time
		newConditions[i].LastHeartbeatTime = metav1.NewTime(c.clock.Now())
	}
	patch, err := generatePatch(newConditions)
	if err != nil {
		return err
	}
	return c.client.RESTClient().Patch(types.StrategicMergePatchType).Resource("nodes").Name(c.nodeName).SubResource("status").Body(patch).Do(ctx).Error()
}

func (c *networkProblemClient) mergeConditionsLastTransitionTime(ctx context.Context, newConditions []corev1.NodeCondition) error {
	var types []corev1.NodeConditionType
	needsGet := false
	for _, condition := range newConditions {
		types = append(types, condition.Type)
		if _, ok := c.cachedConditions[condition.Type]; !ok {
			needsGet = true
		}
	}
	if needsGet {
		conditions, err := c.GetConditions(ctx, types)
		if err != nil {
			return err
		}
		conditionMap := map[corev1.NodeConditionType]corev1.NodeCondition{}
		for _, condition := range conditions {
			conditionMap[condition.Type] = condition
		}
		for _, t := range types {
			if loadedCondition, ok := conditionMap[t]; ok {
				c.cachedConditions[t] = loadedCondition
			}
		}
	}
	for i, condition := range newConditions {
		cachedCondition := c.cachedConditions[condition.Type]
		if cachedCondition.Status == condition.Status && !cachedCondition.LastTransitionTime.Time.IsZero() {
			// keep old transition time
			condition.LastTransitionTime = cachedCondition.LastTransitionTime
			newConditions[i] = condition
		}
		c.cachedConditions[condition.Type] = condition
	}

	return nil
}

func (c *networkProblemClient) Eventf(eventType, source, reason, messageFmt string, args ...interface{}) {
	recorder, found := c.recorders[source]
	if !found {
		// TODO(random-liu): If needed use separate client and QPS limit for event.
		recorder = getEventRecorder(c.log, c.client, c.eventNamespace, c.nodeName, source)
		c.recorders[source] = recorder
	}
	recorder.Eventf(c.nodeRef, eventType, reason, messageFmt, args...)
}

func (c *networkProblemClient) GetNode(ctx context.Context) (*corev1.Node, error) {
	return c.client.Nodes().Get(ctx, c.nodeName, metav1.GetOptions{})
}

// generatePatch generates condition patch.
func generatePatch(conditions []corev1.NodeCondition) ([]byte, error) {
	raw, err := json.Marshal(&conditions)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"status":{"conditions":%s}}`, raw)), nil
}

// getEventRecorder generates a recorder for specific node name and source.
func getEventRecorder(log logrus.FieldLogger, c typedcorev1.CoreV1Interface, namespace, nodeName, source string) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(log.Infof)
	recorder := eventBroadcaster.NewRecorder(runtime.NewScheme(), corev1.EventSource{Component: source, Host: nodeName})
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: c.Events(namespace)})
	return recorder
}

func getNodeRef(namespace, nodeName string) *corev1.ObjectReference {
	// TODO(random-liu): Get node to initialize the node reference
	return &corev1.ObjectReference{
		Kind:      "Node",
		Name:      nodeName,
		UID:       types.UID(nodeName),
		Namespace: namespace,
	}
}
