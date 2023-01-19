// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"math/rand"
	"sort"
	"sync"
)

// SampleConfig holds configuration and state for node sample.
type SampleConfig struct {
	// MaxNodes is the maximum number of sample nodes. If 0, all nodes are selected
	MaxNodes int
	// NodeSampleStore stores node hostnames with floating index for stable sample selection
	NodeSampleStore *NodeSampleStore
}

// NewNodeSampleStore create a new node sample store
func NewNodeSampleStore() *NodeSampleStore {
	return &NodeSampleStore{store: map[string]float64{}}
}

type orderedNode struct {
	hostname string
	index    float64
}

// NodeSampleStore maps all known hostnames to a random number [0.0, 1.0).
// It allows to keep node samples as stable as possible after adding or removing nodes.
type NodeSampleStore struct {
	sync.Mutex
	store map[string]float64
}

// SelectTopNodes selects a stable nodes sample of the given size.
func (s *NodeSampleStore) SelectTopNodes(hostnames map[string]struct{}, size int) map[string]struct{} {
	s.Lock()
	defer s.Unlock()

	for name := range s.store {
		if _, ok := hostnames[name]; !ok {
			delete(s.store, name)
		}
	}

	array := make([]orderedNode, 0, len(hostnames))
	for name := range hostnames {
		index, ok := s.store[name]
		if !ok {
			index = rand.Float64()
			s.store[name] = index
		}
		array = append(array, orderedNode{hostname: name, index: index})
	}

	sort.Slice(array, func(i, j int) bool {
		return array[i].index < array[j].index
	})

	if len(array) > size {
		array = array[:size]
	}

	topNodes := map[string]struct{}{}
	for _, item := range array {
		topNodes[item.hostname] = struct{}{}
	}
	return topNodes
}

// ShuffledSample selects a node sample and shuffles its order
func (sc *SampleConfig) ShuffledSample(cc ClusterConfig) ClusterConfig {
	return ClusterConfig{
		NodeCount:             len(cc.Nodes),
		Nodes:                 CloneAndShuffle(selectSample(sc, cc.Nodes)),
		PodEndpoints:          CloneAndShuffle(selectSample(sc, cc.PodEndpoints)),
		InternalKubeAPIServer: cc.InternalKubeAPIServer,
		KubeAPIServer:         cc.KubeAPIServer,
	}
}

func selectSample[T WithDestHost](pc *SampleConfig, items []T) []T {
	if pc.MaxNodes == 0 || pc.MaxNodes > len(items) {
		return items
	}
	hostnames := map[string]struct{}{}
	for _, item := range items {
		hostnames[item.DestHost()] = struct{}{}
	}
	topNodes := pc.NodeSampleStore.SelectTopNodes(hostnames, pc.MaxNodes)
	var sample []T
	for _, item := range items {
		if _, ok := topNodes[item.DestHost()]; ok {
			sample = append(sample, item)
		}
	}
	return sample
}
