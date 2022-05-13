// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

type Node struct {
	Hostname   string `json:"hostname"`
	InternalIP string `json:"internalIP"`
}

type PodEndpoint struct {
	Nodename string `json:"nodename"`
	Podname  string `json:"podname"`
	PodIP    string `json:"podIP"`
	Port     int32  `json:"port"`
}

type Endpoint struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
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
