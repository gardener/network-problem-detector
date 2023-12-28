/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package problemclient

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	v1 "k8s.io/api/core/v1"
)

// FakeProblemClient is a fake problem client for debug.
type FakeProblemClient struct {
	sync.Mutex
	conditions map[v1.NodeConditionType]v1.NodeCondition
	errors     map[string]error
}

// NewFakeProblemClient creates a new fake problem client.
func NewFakeProblemClient() *FakeProblemClient {
	return &FakeProblemClient{
		conditions: make(map[v1.NodeConditionType]v1.NodeCondition),
		errors:     make(map[string]error),
	}
}

// InjectError injects error to specific function.
func (f *FakeProblemClient) InjectError(fun string, err error) {
	f.Lock()
	defer f.Unlock()
	f.errors[fun] = err
}

// AssertConditions asserts that the internal conditions in fake problem client should match
// the expected conditions.
func (f *FakeProblemClient) AssertConditions(expected []v1.NodeCondition) error {
	conditions := map[v1.NodeConditionType]v1.NodeCondition{}
	for _, condition := range expected {
		conditions[condition.Type] = condition
	}
	if !reflect.DeepEqual(conditions, f.conditions) {
		return fmt.Errorf("expected %+v, got %+v", conditions, f.conditions)
	}
	return nil
}

// SetConditions is a fake mimic of SetConditions, it only update the internal condition cache.
func (f *FakeProblemClient) SetConditions(_ context.Context, conditions []v1.NodeCondition) error {
	f.Lock()
	defer f.Unlock()
	if err, ok := f.errors["SetConditions"]; ok {
		return err
	}
	for _, condition := range conditions {
		f.conditions[condition.Type] = condition
	}
	return nil
}

// GetConditions is a fake mimic of GetConditions, it returns the conditions cached internally.
func (f *FakeProblemClient) GetConditions(_ context.Context, types []v1.NodeConditionType) ([]v1.NodeCondition, error) {
	f.Lock()
	defer f.Unlock()
	if err, ok := f.errors["GetConditions"]; ok {
		return nil, err
	}
	conditions := []v1.NodeCondition{}
	for _, t := range types {
		condition, ok := f.conditions[t]
		if ok {
			conditions = append(conditions, condition)
		}
	}
	return conditions, nil
}

// Eventf does nothing now.
func (f *FakeProblemClient) Eventf(_ string, _, _, _ string, _ ...interface{}) {
}

func (f *FakeProblemClient) GetNode(_ context.Context) (*v1.Node, error) {
	return nil, fmt.Errorf("GetNode() not implemented")
}
