// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package nwpd

type Endpoint struct {
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type ClusterConfig struct {
	// Nodes are the known nodes.
	Nodes []Node `json:"nodes,omitempty"`
	// PodEndpoints are the known pods of the 'nwpd-agent-pod-net' daemon set.
	PodEndpoints []PodEndpoint `json:"podEndpoints,omitempty"`
}

func (cc ClusterConfig) Shuffled() ClusterConfig {
	return ClusterConfig{
		Nodes:        CloneAndShuffleNodes(cc.Nodes),
		PodEndpoints: CloneAndShufflePodEndpoints(cc.PodEndpoints),
	}
}
