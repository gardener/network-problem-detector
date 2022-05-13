// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"net"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func GetAPIServerEndpoint(clientset *kubernetes.Clientset) (*config.Endpoint, error) {
	ctx := context.Background()
	shootInfo, err := clientset.CoreV1().ConfigMaps(common.NamespaceKubeSystem).Get(ctx, "shoot-info", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting configmap %s/shoot-info", common.NamespaceKubeSystem)
	}

	domain, ok := shootInfo.Data["domain"]
	if !ok {
		return nil, fmt.Errorf("missing 'domain' key in configmap %s/shoot-info", common.NamespaceKubeSystem)
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

func BuildClusterConfig(nodes []*corev1.Node, agentPods []*corev1.Pod) (config.ClusterConfig, error) {
	clusterConfig := config.ClusterConfig{}

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
			Port:     common.PodNetPodGRPCPort,
		})
	}

	return clusterConfig, nil
}
