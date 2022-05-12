// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	//gomegatypes "github.com/onsi/gomega/types"
)

var _ = Describe("parser", func() {
	var (
		config1     = nwpd.RunnerConfig{JobID: "test", Period: 15 * time.Second}
		clusterCfg1 = nwpd.ClusterConfig{
			Nodes: []nwpd.Node{
				{Hostname: "node1", InternalIP: "10.0.0.11"},
				{Hostname: "node2", InternalIP: "10.0.0.12"},
			},
		}
		config2     = nwpd.RunnerConfig{JobID: "test", Period: 10 * time.Second}
		clusterCfg2 = nwpd.ClusterConfig{
			Nodes: []nwpd.Node{
				{Hostname: "node3", InternalIP: "10.0.0.13"},
				{Hostname: "node4", InternalIP: "10.0.0.14"},
			},
		}
		endpoints1 = []nwpd.Endpoint{
			{Hostname: "server", IP: "10.0.0.9", Port: 55555},
		}
		endpoints2 = []nwpd.Endpoint{
			{Hostname: "node1", IP: "10.0.0.11", Port: 55555},
			{Hostname: "node2", IP: "10.0.0.12", Port: 55555},
		}
	)

	DescribeTable("should parse runner commands",
		func(clusterCfg nwpd.ClusterConfig, config nwpd.RunnerConfig, args []string, expected interface{}) {
			actual, err := Parse(clusterCfg, config, args, false)
			switch v := expected.(type) {
			case nwpd.Runner:
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
		Entry("discoverMDNS", clusterCfg1, config1, []string{"discoverMDNS"}, NewDiscoverMDNS(config1)),
	)
})
