// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

type WithDestHost interface {
	DestHost() string
}

type Node struct {
	Hostname   string `json:"hostname"`
	InternalIP string `json:"internalIP"`
}

func (n Node) DestHost() string {
	return n.Hostname
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

func (e Endpoint) DestHost() string {
	return e.Hostname
}

type ClusterConfig struct {
	// Nodes are the known nodes.
	Nodes []Node `json:"nodes,omitempty"`
	// PodEndpoints are the known pods of the 'nwpd-agent-pod-net' daemon set.
	PodEndpoints []PodEndpoint `json:"podEndpoints,omitempty"`
	// InternalKubeAPIServer is the discovered internal address of the kube-apiserver
	InternalKubeAPIServer *Endpoint `json:"internalKubeAPIServer,omitempty"`
	// KubeAPIServer is the discovered external address of the kube-apiserver (relies on Gardener shoot-info)
	KubeAPIServer *Endpoint `json:"kubeAPIServer,omitempty"`
}

func (cc ClusterConfig) Shuffled() ClusterConfig {
	return ClusterConfig{
		Nodes:                 CloneAndShuffle(cc.Nodes),
		PodEndpoints:          CloneAndShuffle(cc.PodEndpoints),
		InternalKubeAPIServer: cc.InternalKubeAPIServer,
		KubeAPIServer:         cc.KubeAPIServer,
	}
}
