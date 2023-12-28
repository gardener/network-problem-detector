/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package condition

import (
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/problemclient"
	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/types"

	v1 "k8s.io/api/core/v1"
)

const heartbeatPeriod = 1 * time.Minute

func newTestManager() (*conditionManager, *problemclient.FakeProblemClient, *clocktesting.FakeClock) {
	fakeClient := problemclient.NewFakeProblemClient()
	fakeClock := clocktesting.NewFakeClock(time.Now())
	log := logrus.New()
	manager := NewManager(log, fakeClient, fakeClock, heartbeatPeriod)
	return manager.(*conditionManager), fakeClient, fakeClock
}

func newTestCondition(condition string) types.Condition {
	return types.Condition{
		Type:       condition,
		Status:     types.True,
		Transition: time.Now(),
		Reason:     "TestReason",
		Message:    "test message",
	}
}

func TestNeedUpdates(t *testing.T) {
	m, _, _ := newTestManager()
	var c types.Condition
	for _, testCase := range []struct {
		name      string
		condition string
		status    types.ConditionStatus
		update    bool
	}{
		{
			name:      "Init condition needs update",
			condition: "TestCondition",
			update:    true,
		},
		{
			name: "Same condition doesn't need update",
			// not set condition, the test will reuse the condition in last case.
			update: false,
		},
		{
			name:      "Same condition with different transition timestamp but same status need no update",
			condition: "TestCondition",
			update:    false,
		},
		{
			name:      "Same condition with different status need update",
			condition: "TestCondition",
			status:    types.False,
			update:    true,
		},
		{
			name:      "New condition needs update",
			condition: "TestConditionNew",
			update:    true,
		},
	} {
		tc := testCase
		t.Log(tc.name)
		if tc.condition != "" {
			// Guarantee that the time advances before creating a new condition.
			for now := time.Now(); now == time.Now(); {
				time.Sleep(1 * time.Microsecond)
			}
			c = newTestCondition(tc.condition)
			if tc.status != "" {
				c.Status = tc.status
			}
		}
		m.UpdateCondition(c)
		assert.Equal(t, tc.update, m.needUpdates(), tc.name)
		assert.Equal(t, c, m.conditions[c.Type], tc.name)
	}
}

func TestGetConditions(t *testing.T) {
	m, _, _ := newTestManager()
	assert.Empty(t, m.GetConditions())
	testCondition1 := newTestCondition("TestCondition1")
	testCondition2 := newTestCondition("TestCondition2")
	m.UpdateCondition(testCondition1)
	m.UpdateCondition(testCondition2)
	assert.True(t, m.needUpdates())
	assert.Contains(t, m.GetConditions(), testCondition1)
	assert.Contains(t, m.GetConditions(), testCondition2)
}

func TestResync(t *testing.T) {
	m, fakeClient, fakeClock := newTestManager()
	condition := newTestCondition("TestCondition")
	m.conditions = map[string]types.Condition{condition.Type: condition}
	m.sync()
	expected := []v1.NodeCondition{types.ConvertToAPICondition(condition)}
	assert.Nil(t, fakeClient.AssertConditions(expected), "Condition should be updated via client")

	assert.False(t, m.needResync(), "Should not resync before resync period")
	fakeClock.Step(resyncPeriod)
	assert.False(t, m.needResync(), "Should not resync after resync period without resync needed")

	fakeClient.InjectError("SetConditions", fmt.Errorf("injected error"))
	m.sync()

	assert.False(t, m.needResync(), "Should not resync before resync period")
	fakeClock.Step(resyncPeriod)
	assert.True(t, m.needResync(), "Should resync after resync period and resync is needed")
}

func TestHeartbeat(t *testing.T) {
	m, fakeClient, fakeClock := newTestManager()
	condition := newTestCondition("TestCondition")
	m.conditions = map[string]types.Condition{condition.Type: condition}
	m.sync()
	expected := []v1.NodeCondition{types.ConvertToAPICondition(condition)}
	assert.Nil(t, fakeClient.AssertConditions(expected), "Condition should be updated via client")

	assert.False(t, m.needHeartbeat(), "Should not heartbeat before heartbeat period")

	fakeClock.Step(heartbeatPeriod)
	assert.True(t, m.needHeartbeat(), "Should heartbeat after heartbeat period")
}
