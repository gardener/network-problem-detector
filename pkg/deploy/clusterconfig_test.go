// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy_test

import (
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/deploy"
)

var _ = Describe("BuildClusterConfig", func() {
	It("should build cluster config correctly", func() {
		log := logrus.New()
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

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(len(clusterConfig.Nodes[0].InternalIPs)).To(Equal(1))
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPs, ("192.168.1.1"))).To(BeTrue())
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 addresses", func() {
		log := logrus.New()
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

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(len(clusterConfig.Nodes[0].InternalIPsV6)).To(Equal(1))
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPsV6, ("2001:db8::1"))).To(BeTrue())
		Expect(clusterConfig.PodEndpointsV6[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpointsV6[0].PodIP).To(Equal("2001:db8::2"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses in nodes but only IPv4 for pods.", func() {
		log := logrus.New()
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

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(len(clusterConfig.Nodes[0].InternalIPs)).To(Equal(1))
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPs, ("192.168.1.1"))).To(BeTrue())
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses in nodes but only IPv4 for pods.", func() {
		log := logrus.New()
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

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(len(clusterConfig.Nodes[0].InternalIPs)).To(Equal(1))
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPs, ("192.168.1.1"))).To(BeTrue())
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})

	It("should build cluster config correctly with IPv6 and IPv4 addresses for nodes and for pods.", func() {
		log := logrus.New()
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

		clusterConfig, err := deploy.BuildClusterConfig(log, nodes, agentPods, internalKubeAPIServer, kubeAPIServer)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterConfig).NotTo(BeNil())
		Expect(clusterConfig.NodeCount).To(Equal(1))
		Expect(clusterConfig.Nodes[0].Hostname).To(Equal("node1"))
		Expect(len(clusterConfig.Nodes[0].InternalIPs)).To(Equal(1))
		Expect(len(clusterConfig.Nodes[0].InternalIPsV6)).To(Equal(1))
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPs, ("192.168.1.1"))).To(BeTrue())
		Expect(slices.Contains(clusterConfig.Nodes[0].InternalIPsV6, ("2001:db8::1"))).To(BeTrue())
		Expect(clusterConfig.PodEndpoints[0].Nodename).To(Equal("node1"))
		Expect(clusterConfig.PodEndpoints[0].PodIP).To(Equal("10.0.0.1"))
	})
})
