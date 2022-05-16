// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	//gomegatypes "github.com/onsi/gomega/types"
)

func init() {
	config.DisableShuffleForTesting = true
}

var _ = Describe("parser", func() {
	var (
		config1     = RunnerConfig{JobID: "test", Period: 15 * time.Second}
		clusterCfg1 = config.ClusterConfig{
			Nodes: []config.Node{
				{Hostname: "node1", InternalIP: "10.0.0.11"},
				{Hostname: "node2", InternalIP: "10.0.0.12"},
			},
			PodEndpoints: []config.PodEndpoint{
				{Nodename: "node1", Podname: "pod1", PodIP: "10.128.0.11", Port: 1234},
				{Nodename: "node2", Podname: "pod2", PodIP: "10.128.0.12", Port: 1234},
			},
			InternalKubeAPIServer: &config.Endpoint{
				Hostname: "kubernetes",
				IP:       "100.64.0.1",
				Port:     443,
			},
			KubeAPIServer: &config.Endpoint{
				Hostname: "api.shoot.domain.com",
				IP:       "1.2.3.4",
				Port:     443,
			},
		}
		config2     = RunnerConfig{JobID: "test", Period: 10 * time.Second}
		clusterCfg2 = config.ClusterConfig{
			Nodes: []config.Node{
				{Hostname: "node3", InternalIP: "10.0.0.13"},
				{Hostname: "node4", InternalIP: "10.0.0.14"},
			},
		}
		endpoints1 = []config.Endpoint{
			{Hostname: "server", IP: "10.0.0.9", Port: 55555},
		}
		endpoints2 = []config.Endpoint{
			{Hostname: "node1", IP: "10.0.0.11", Port: 55555},
			{Hostname: "node2", IP: "10.0.0.12", Port: 55555},
		}
		endpointsPods = []config.Endpoint{
			{Hostname: "node1", IP: "10.128.0.11", Port: 1234},
			{Hostname: "node2", IP: "10.128.0.12", Port: 1234},
		}
		endpointsInternalKubeApiServer = []config.Endpoint{
			{Hostname: "kubernetes", IP: "100.64.0.1", Port: 443},
		}
		endpointsKubeApiServer = []config.Endpoint{
			{Hostname: "api.shoot.domain.com", IP: "1.2.3.4", Port: 443},
		}
	)

	DescribeTable("should parse runner commands",
		func(clusterCfg config.ClusterConfig, config RunnerConfig, args []string, expected interface{}) {
			actual, err := Parse(clusterCfg, config, args, false)
			switch v := expected.(type) {
			case Runner:
				Expect(err).To(BeNil())
				Expect(actual).To(Equal(v))
			case string:
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring(v))
			default:
				Fail("unexpected type")
			}
		},

		Entry("pingHost", clusterCfg1, config1, []string{"pingHost"}, NewPingHost(clusterCfg1.Nodes, config1)),
		Entry("pingHost with hosts and custom period", clusterCfg1, config1, []string{"pingHost", "--period", "10s", "--hosts", "node3:10.0.0.13,node4:10.0.0.14"}, NewPingHost(clusterCfg2.Nodes, config2)),
		Entry("pingHost - invalid option", clusterCfg1, config1, []string{"pingHost", "--foo"}, "unknown flag: --foo"),
		Entry("pingHost - invalid host", clusterCfg1, config1, []string{"pingHost", "--hosts", "node3"}, "invalid host node3"),
		Entry("checkTCPPort", clusterCfg1, config1, []string{"checkTCPPort", "--period", "10s", "--endpoints", "server:10.0.0.9:55555"}, NewCheckTCPPort(endpoints1, config2)),
		Entry("checkTCPPort - missing endpoints", clusterCfg1, config1, []string{"checkTCPPort"}, "no endpoints"),
		Entry("checkTCPPort - invalid endpoint", clusterCfg1, config1, []string{"checkTCPPort", "--endpoints", "server:10.0.0.9:x"}, "invalid endpoint port x"),
		Entry("checkTCPPort with node port", clusterCfg1, config1, []string{"checkTCPPort", "--node-port", "55555"}, NewCheckTCPPort(endpoints2, config1)),
		Entry("checkTCPPort with pod endpoints", clusterCfg1, config1, []string{"checkTCPPort", "--endpoints-of-pod-ds"}, NewCheckTCPPort(endpointsPods, config1)),
		Entry("checkTCPPort with internal kube-apiserver endpoints", clusterCfg1, config1, []string{"checkTCPPort", "--endpoint-internal-kube-apiserver"}, NewCheckTCPPort(endpointsInternalKubeApiServer, config1)),
		Entry("checkTCPPort with external kube-apiserver endpoints", clusterCfg1, config1, []string{"checkTCPPort", "--endpoint-external-kube-apiserver"}, NewCheckTCPPort(endpointsKubeApiServer, config1)),
		Entry("discoverMDNS", clusterCfg1, config1, []string{"discoverMDNS"}, NewDiscoverMDNS(config1)),
	)
})
