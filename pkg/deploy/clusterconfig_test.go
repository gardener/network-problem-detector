// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy_test

import (
	"net"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/deploy"
)

var _ = Describe("BuildClusterConfig", func() {
	var nodeCIDRs []net.IPNet
	BeforeEach(func() {
		_, v4, _ := net.ParseCIDR("192.168.1.0/24")
		_, v6A, _ := net.ParseCIDR("2001:db8::/48")
		_, v6B, _ := net.ParseCIDR("2001:db8:1::/48")
		nodeCIDRs = []net.IPNet{*v4, *v6A, *v6B}
	})
	It("should build cluster config correctly", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 addresses", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "2001:db8::2"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "2001:db8::3",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "2001:db8::4",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPsV6).To(ConsistOf("2001:db8::1"))
		Expect(clusterConfig.PodEndpointsV6[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpointsV6[0].PodIP).To(Equal("2001:db8::2"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses in nodes but only IPv4 for pods.", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses in nodes but only IPv4 for pods.", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
						{IP: "10.0.0.2"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
						{IP: "2001:db8::2"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses for nodes and for pods.", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
						{IP: "2001:db8::2"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		Expect(clusterConfig.Nodes[0].InternalIPsV6).To(ConsistOf("2001:db8::1"))
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly when one pod has nil IP address", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: ""}, // nil/empty IP
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		// Should only have one pod endpoint (the one with valid IP)
		Expect(clusterConfig.PodEndpoints).To(HaveLen(1))
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly when all pods have nil IP addresses", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: ""}, // nil/empty IP
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "invalid-ip"}, // invalid IP
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		// Should have no pod endpoints since all pods have invalid IPs
		Expect(clusterConfig.PodEndpoints).To(BeEmpty())
		Expect(clusterConfig.PodEndpointsV6).To(BeEmpty())
	})

	It("should only include IPs from the node CIDRs in the cluster config if a node has multiple IPs", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeInternalIP, Address: "10.180.1.1"},
						{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
						{Type: corev1.NodeInternalIP, Address: "2a05:d018:a7c:d500::1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.180.1.2"},
						{Type: corev1.NodeInternalIP, Address: "192.168.1.2"},
						{Type: corev1.NodeInternalIP, Address: "2a05:d018:a7c:d500::2"},
						{Type: corev1.NodeInternalIP, Address: "2001:db8:1::2"},
						{Type: corev1.NodeHostName, Address: "node2"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
						{IP: "2001:db8::1"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.2"},
						{IP: "2001:db8::2"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node2",
				},
			},
		}
		internalKubeAPIServer := &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}
		kubeAPIServer := &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}
		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer, nodeCIDRs)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		// should only include the IPs from the node CIDRs in the cluster config (IPv4 and IPv6)
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1"))
		Expect(clusterConfig.Nodes[0].InternalIPsV6).To(ConsistOf("2001:db8::1"))
		Expect(clusterConfig.Nodes[1].InternalIPs).To(ConsistOf("192.168.1.2"))
		Expect(clusterConfig.Nodes[1].InternalIPsV6).To(ConsistOf("2001:db8:1::2"))
	})
	It("should include all IPs when no node CIDRs are provided", func() {
		log := logr.Discard()
		nodes := []*corev1.Node{
			{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "192.168.1.1"},
						{Type: corev1.NodeInternalIP, Address: "10.180.1.1"},
						{Type: corev1.NodeHostName, Address: "node1"},
					},
				},
			},
		}
		agentPods := []*corev1.Pod{
			{
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					PodIPs: []corev1.PodIP{
						{IP: "10.0.0.1"},
					},
				},
				Spec: corev1.PodSpec{
					NodeName: "node1",
				},
			},
		}

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, &config.Endpoint{
			Hostname: "internal-api-server",
			IP:       "192.168.1.2",
			Port:     443,
		}, &config.Endpoint{
			Hostname: "api-server",
			IP:       "192.168.1.3",
			Port:     443,
		}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].InternalIPs).To(ConsistOf("192.168.1.1", "10.180.1.1"))
	})
})

var _ = Describe("GetNodeNetworksFromShootInfo", func() {
	Context("correctly configured shoot info", func() {
		It("should return the IPv4 network for an IPv4-only cluster", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "10.180.0.0/16",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(1))
			Expect(nodeCIDRs[0].String()).To(Equal("10.180.0.0/16"))
		})
		It("should return the IPv6 network for an IPv6-only cluster", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "2a05:d018:a7c:d500::/56",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(1))
			Expect(nodeCIDRs[0].String()).To(Equal("2a05:d018:a7c:d500::/56"))
		})
		It("should return both IPv4 and IPv6 networks for a dual-stack cluster", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "10.180.0.0/16,2a05:d018:a7c:d500::/56",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(2))
			Expect(nodeCIDRs[0].String()).To(Equal("10.180.0.0/16"))
			Expect(nodeCIDRs[1].String()).To(Equal("2a05:d018:a7c:d500::/56"))
		})
	})
	Context("misconfigured shoot info", func() {
		It("should return an error for a missing nodeNetworks key", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("missing 'nodeNetworks' key")))
			Expect(nodeCIDRs).To(BeNil())
		})
		It("should return an error for an empty nodeNetworks value", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("empty 'nodeNetworks' value")))
			Expect(nodeCIDRs).To(BeNil())
		})
		It("should return all CIDRs for a nodeNetworks value with more than two CIDRs", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "10.180.0.0/16,2a05:d018:a7c:d500::/56,2a05:d018:a7c:d501::/56",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(3))
		})
		It("should return an error for an invalid nodeNetworks value", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "invalid-network",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("invalid 'nodeNetworks' value")))
			Expect(nodeCIDRs).To(BeNil())
		})
		It("should return all CIDRs for a nodeNetworks value with two IPv4 CIDRs", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "10.180.0.0/16,192.168.0.0/16",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(2))
		})
		It("should return all CIDRs for a nodeNetworks value with two IPv6 CIDRs", func() {
			shootInfo := &corev1.ConfigMap{
				Data: map[string]string{
					"nodeNetworks": "2a05:d018:a7c:d500::/56,2a05:d018:a7c:d501::/56",
				},
			}
			nodeCIDRs, err := deploy.GetNodeNetworksFromShootInfo(shootInfo)
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeCIDRs).To(HaveLen(2))
		})
	})
})
