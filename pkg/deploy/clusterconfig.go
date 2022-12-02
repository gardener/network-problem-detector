// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	corev1 "k8s.io/api/core/v1"
)

func BuildClusterConfig(nodes []*corev1.Node, agentPods []*corev1.Pod,
	internalKubeAPIServer, kubeAPIServer *config.Endpoint) (*config.ClusterConfig, error) {
	clusterConfig := &config.ClusterConfig{
		InternalKubeAPIServer: internalKubeAPIServer,
		KubeAPIServer:         kubeAPIServer,
	}

	for _, n := range nodes {
		hostname := ""
		ip := ""
		for _, addr := range n.Status.Addresses {
			switch addr.Type {
			case "Hostname":
				hostname = addr.Address
			case "InternalIP":
				ip = addr.Address
			}
		}
		if hostname == "" || ip == "" {
			return clusterConfig, fmt.Errorf("invalid node: %s", n.Name)
		}
		clusterConfig.Nodes = append(clusterConfig.Nodes, config.Node{
			Hostname:   hostname,
			InternalIP: ip,
		})
	}

	for _, p := range agentPods {
		clusterConfig.PodEndpoints = append(clusterConfig.PodEndpoints, config.PodEndpoint{
			Nodename: p.Spec.NodeName,
			Podname:  p.Name,
			PodIP:    p.Status.PodIP,
			Port:     common.PodNetPodHttpPort,
		})
	}

	sort.Slice(clusterConfig.Nodes, func(i, j int) bool {
		return strings.Compare(clusterConfig.Nodes[i].Hostname, clusterConfig.Nodes[j].Hostname) < 0
	})
	sort.Slice(clusterConfig.PodEndpoints, func(i, j int) bool {
		cmp := strings.Compare(clusterConfig.PodEndpoints[i].Nodename, clusterConfig.PodEndpoints[j].Nodename)
		if cmp == 0 {
			cmp = strings.Compare(clusterConfig.PodEndpoints[i].Podname, clusterConfig.PodEndpoints[j].Podname)
		}
		return cmp < 0
	})

	return clusterConfig, nil
}

func GetAPIServerEndpointFromShootInfo(shootInfo *corev1.ConfigMap) (*config.Endpoint, error) {
	domain, ok := shootInfo.Data["domain"]
	if !ok {
		return nil, fmt.Errorf("missing 'domain' key in configmap %s/%s", common.NamespaceKubeSystem, common.NameGardenerShootInfo)
	}
	apiServer := "api." + domain
	ips, err := net.LookupIP(apiServer)
	if err != nil {
		return nil, fmt.Errorf("error looking up shoot apiserver %s: %s", apiServer, err)
	}
	return &config.Endpoint{
		Hostname: apiServer,
		IP:       ips[0].String(),
		Port:     443,
	}, nil
}
