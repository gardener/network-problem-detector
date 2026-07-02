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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
)

func arePodsOfIPFamily(agentPods []*corev1.Pod, ipFamily string) bool {
	for _, p := range agentPods {
		found := false
		hasValidIP := false
		for _, podIPEntry := range p.Status.PodIPs {
			podIP := net.ParseIP(podIPEntry.IP)
			if podIP == nil {
				continue
			}
			hasValidIP = true
			if ipFamily == "IPv4" && podIP.To4() != nil {
				found = true
				break
			}
			if ipFamily == "IPv6" && podIP.To4() == nil {
				found = true
				break
			}
		}
		// Only return false if the pod has valid IPs but none of the requested family
		if hasValidIP && !found {
			return false
		}
	}
	return true
}

func BuildClusterConfig(
	log logr.Logger,
	nodes []*corev1.Node,
	agentPods []*corev1.Pod,
	internalKubeAPIServer,
	kubeAPIServer *config.Endpoint,
	nodeCIDRs []net.IPNet,
) (*config.ClusterConfig, error) {
	clusterConfig := &config.ClusterConfig{
		InternalKubeAPIServer: internalKubeAPIServer,
		KubeAPIServer:         kubeAPIServer,
	}

	// Determine the IP family of the pods once
	arePodsIPv4 := arePodsOfIPFamily(agentPods, "IPv4")
	arePodsIPv6 := arePodsOfIPFamily(agentPods, "IPv6")

	nodeNames := common.StringSet{}
	for _, n := range nodes {
		hostname := ""
		ips := []string{}
		ipsV6 := []string{}
		for _, addr := range n.Status.Addresses {
			switch addr.Type {
			case "Hostname":
				hostname = addr.Address
			case "InternalIP":
				ip := net.ParseIP(addr.Address)
				if ip == nil {
					continue
				}
				if len(nodeCIDRs) == 0 { // can happen if not ShootInfo is available, e..g. with the --ignore-gardener-kube-api-server option
					if ip.To4() != nil && arePodsIPv4 {
						ips = append(ips, addr.Address)
					} else if ip.To4() == nil && arePodsIPv6 {
						ipsV6 = append(ipsV6, addr.Address)
					}
				} else {
					for _, cidr := range nodeCIDRs {
						if cidr.Contains(ip) {
							if ip.To4() != nil && arePodsIPv4 {
								ips = append(ips, addr.Address)
							} else if ip.To4() == nil && arePodsIPv6 {
								ipsV6 = append(ipsV6, addr.Address)
							}
							break
						}
					}
				}
			}
		}
		if len(ips) == 0 && len(ipsV6) == 0 {
			log.Info("ignore node without internalIP", "node", n.Name)
			continue
		}
		if hostname == "" {
			hostname = n.Name
		}
		clusterConfig.Nodes = append(clusterConfig.Nodes, config.Node{
			Hostname:      hostname,
			InternalIPs:   ips,
			InternalIPsV6: ipsV6,
		})
		nodeNames.Add(hostname)
	}

	for _, p := range agentPods {
		if p.Status.Phase != corev1.PodRunning || !nodeNames.Contains(p.Spec.NodeName) {
			continue
		}
		for _, podIP := range p.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip == nil {
				log.Info("ignore pod with invalid podIP", "pod", fmt.Sprintf("%s/%s", p.Namespace, p.Name), "podIP", podIP.IP)
				continue
			}
			if ip.To4() != nil {
				clusterConfig.PodEndpoints = append(clusterConfig.PodEndpoints, config.PodEndpoint{
					Nodename: p.Spec.NodeName,
					Podname:  p.Name,
					PodIP:    podIP.IP,
					Port:     common.PodNetPodHTTPPort,
				})
			} else {
				clusterConfig.PodEndpointsV6 = append(clusterConfig.PodEndpointsV6, config.PodEndpoint{
					Nodename: p.Spec.NodeName,
					Podname:  p.Name,
					PodIP:    podIP.IP,
					Port:     common.PodNetPodHTTPPort,
				})
			}
		}
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
	sort.Slice(clusterConfig.PodEndpointsV6, func(i, j int) bool {
		cmp := strings.Compare(clusterConfig.PodEndpointsV6[i].Nodename, clusterConfig.PodEndpointsV6[j].Nodename)
		if cmp == 0 {
			cmp = strings.Compare(clusterConfig.PodEndpointsV6[i].Podname, clusterConfig.PodEndpointsV6[j].Podname)
		}
		return cmp < 0
	})

	clusterConfig.NodeCount = len(clusterConfig.Nodes)
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

// Extract IPv4 and IPv6 node networks from the ShootInfo ConfigMap.
func GetNodeNetworksFromShootInfo(shootInfo *corev1.ConfigMap) ([]net.IPNet, error) {
	var networks []net.IPNet
	nodeNetworks, ok := shootInfo.Data["nodeNetworks"]
	if !ok {
		return nil, fmt.Errorf("missing 'nodeNetworks' key")
	}
	if nodeNetworks == "" {
		return nil, fmt.Errorf("empty 'nodeNetworks' value")
	}
	// Split the nodeNetworks value into individual CIDRs
	cidrs := strings.Split(nodeNetworks, ",")
	if len(cidrs) > 2 {
		return nil, fmt.Errorf("invalid 'nodeNetworks' value (more than 2 CIDRs): %s", nodeNetworks)
	}
	var ipv4Found, ipv6Found bool
	for i, cidr := range cidrs {
		cidrs[i] = strings.TrimSpace(cidr)
		_, parsedCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid 'nodeNetworks' value: %s", err)
		}
		if parsedCIDR.IP.To4() != nil {
			if ipv4Found {
				return nil, fmt.Errorf("invalid 'nodeNetworks' value (multiple IPv4 CIDRs): %s", nodeNetworks)
			}
			ipv4Found = true
			networks = append(networks, *parsedCIDR)
		} else {
			if ipv6Found {
				return nil, fmt.Errorf("invalid 'nodeNetworks' value (multiple IPv6 CIDRs): %s", nodeNetworks)
			}
			ipv6Found = true
			networks = append(networks, *parsedCIDR)
		}
	}
	return networks, nil
}
