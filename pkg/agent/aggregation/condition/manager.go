/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// based on: https://github.com/kubernetes/node-problem-detector/blob/9c24be2da421dedc7e8bccf0e58e7d4c5230a141/pkg/exporters/k8sexporter/condition/manager.go

package condition

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/problemclient"
	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/types"

	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"
)

const (
	// updatePeriod is the period at which condition manager checks update.
	updatePeriod = 5 * time.Second
	// resyncPeriod is the period at which condition manager does resync, only updates when needed.
	resyncPeriod = 10 * time.Second
	// maxSyncFactor is the factor for longer wait after failed sync.
	maxSyncFactor = 10
)

// Manager synchronizes node conditions with the apiserver with problem client.
// It makes sure that:
// 1) Node conditions are updated to apiserver as soon as possible.
// 2) Node problem detector won't flood apiserver.
// 3) No one else could change the node conditions maintained by node problem detector.
// Manager checks every updatePeriod to see whether there is node condition update. If there are any,
// it will synchronize with the apiserver. This addresses 1) and 2).
// Manager synchronizes with apiserver every resyncPeriod no matter there is node condition update or
// not. This addresses 3).
type Manager interface {
	// Start starts the condition manager.
	Start()
	// UpdateCondition updates a specific condition.
	UpdateCondition(types.Condition)
	// GetConditions returns all current conditions.
	GetConditions() []types.Condition
}

type conditionManager struct {
	// Only 2 fields will be accessed by more than one goroutines at the same time:
	// * `updates`: updates will be written by random caller and the sync routine,
	// so it needs to be protected by write lock in both `UpdateCondition` and
	// `needUpdates`.
	// * `conditions`: conditions will only be written in the sync routine, but
	// it will be read by random caller and the sync routine. So it needs to be
	// protected by write lock in `needUpdates` and read lock in `GetConditions`.
	// No lock is needed in `sync`, because it is in the same goroutine with the
	// write operation.
	sync.RWMutex
	log         logrus.FieldLogger
	clock       clock.WithTicker
	latestTry   time.Time
	failedSyncs atomic.Int32
	client      problemclient.Client
	updates     map[string]types.Condition
	conditions  map[string]types.Condition
	// heartbeatPeriod is the period at which condition manager does forcibly sync with apiserver.
	heartbeatPeriod time.Duration
}

// NewManager creates a condition manager.
func NewManager(log logrus.FieldLogger, client problemclient.Client, clock clock.WithTicker, heartbeatPeriod time.Duration) Manager {
	return &conditionManager{
		log:             log,
		client:          client,
		clock:           clock,
		updates:         make(map[string]types.Condition),
		conditions:      make(map[string]types.Condition),
		heartbeatPeriod: heartbeatPeriod,
	}
}

func (c *conditionManager) Start() {
	go c.syncLoop()
}

func (c *conditionManager) UpdateCondition(condition types.Condition) {
	c.Lock()
	defer c.Unlock()
	// New node condition will override the old condition, because we only need the newest
	// condition for each condition type.
	c.updates[condition.Type] = condition
	c.log.WithFields(logrus.Fields{
		"type":    condition.Type,
		"status":  condition.Status,
		"reason":  condition.Reason,
		"message": condition.Message,
	}).Info("updated condition")
}

func (c *conditionManager) GetConditions() []types.Condition {
	c.RLock()
	defer c.RUnlock()
	var conditions []types.Condition
	for _, condition := range c.conditions {
		conditions = append(conditions, condition)
	}
	return conditions
}

func (c *conditionManager) getCoreConditionsWithSources() ([]corev1.NodeCondition, []string) {
	c.RLock()
	defer c.RUnlock()
	var conditions []corev1.NodeCondition
	var sources []string
	for _, condition := range c.GetConditions() {
		conditions = append(conditions, types.ConvertToAPICondition(condition))
		sources = append(sources, condition.Source)
	}
	return conditions, sources
}

func (c *conditionManager) syncLoop() {
	ticker := c.clock.NewTicker(updatePeriod)
	defer ticker.Stop()
	for {
		<-ticker.C()
		if c.needUpdates() || c.needResync() || c.needHeartbeat() {
			c.sync()
		}
	}
}

// needUpdates checks whether there are recent updates.
func (c *conditionManager) needUpdates() bool {
	c.Lock()
	defer c.Unlock()
	needUpdate := false
	for t, update := range c.updates {
		if !reflect.DeepEqual(c.conditions[t], update) {
			needUpdate = update.Status != c.conditions[t].Status
			if needUpdate && update.Transition.IsZero() {
				update.Transition = time.Now()
			}
			c.conditions[t] = update
		}
		delete(c.updates, t)
	}
	return needUpdate
}

// needResync checks whether a resync is needed.
func (c *conditionManager) needResync() bool {
	failedSync := c.failedSyncs.Load()
	if failedSync == 0 {
		return false
	}
	return c.clock.Since(c.latestTry) >= resyncPeriod+time.Duration(failedSync-1)*updatePeriod
}

// needHeartbeat checks whether a forcible heartbeat is needed.
func (c *conditionManager) needHeartbeat() bool {
	return c.clock.Since(c.latestTry) >= c.heartbeatPeriod
}

// sync synchronizes node conditions with the apiserver.
func (c *conditionManager) sync() {
	c.latestTry = c.clock.Now()
	conditions, sources := c.getCoreConditionsWithSources()
	if len(conditions) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.client.SetConditions(ctx, conditions); err != nil {
			// The conditions will be updated again in future sync
			c.log.Errorf("failed to update node conditions: %v", err)
			if c.failedSyncs.Load() < maxSyncFactor {
				c.failedSyncs.Inc()
			}
			return
		}
		c.log.Infof("SetConditions was successful")
		for i, condition := range conditions {
			if condition.Status == corev1.ConditionTrue {
				c.client.Eventf(corev1.EventTypeWarning, sources[i], condition.Reason, condition.Message)
			}
		}
	}
	c.failedSyncs.Store(0)
}
