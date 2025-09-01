// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"os"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	config.DisableShuffleForTesting = true
}

var _ = Describe("parser", func() {
	var (
		config1     = RunnerConfig{Job: config.Job{JobID: "test"}, Period: 15 * time.Second}
		clusterCfg1 = config.ClusterConfig{
			NodeCount: 2,
			Nodes: []config.Node{
				{Hostname: "node1", InternalIPs: []string{"10.0.0.11"}},
				{Hostname: "node2", InternalIPs: []string{"10.0.0.12"}},
			},
			PodEndpoints: []config.PodEndpoint{
				{Nodename: "node1", Podname: "pod1", PodIP: "10.128.0.11", Port: 1234},
				{Nodename: "node2", Podname: "pod2", PodIP: "10.128.0.12", Port: 1234},
			},
			InternalKubeAPIServer: &config.Endpoint{
				Hostname: common.DomainNameKubernetesService,
				IP:       "100.64.0.1",
				Port:     443,
			},
			KubeAPIServer: &config.Endpoint{
				Hostname: "api.shoot.domain.com",
				IP:       "1.2.3.4",
				Port:     443,
			},
		}
		config2     = RunnerConfig{Job: config.Job{JobID: "test"}, Period: 10 * time.Second}
		clusterCfg2 = config.ClusterConfig{
			NodeCount: 2,
			Nodes: []config.Node{
				{Hostname: "node3", InternalIPs: []string{"10.0.0.13"}},
				{Hostname: "node4", InternalIPs: []string{"10.0.0.14"}},
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
		endpointsInternalKubeAPIServer = []config.Endpoint{
			{Hostname: common.DomainNameKubernetesService, IP: "100.64.0.1", Port: 443},
		}

		endpointsKubeAPIServer = []config.Endpoint{
			{Hostname: "api.shoot.domain.com", IP: "1.2.3.4", Port: 443},
		}
		httpsEndpointsKubeAPIServer = []CheckHTTPSEndpoint{
			{
				Endpoint:      config.Endpoint{Hostname: "api.shoot.domain.com", IP: "", Port: 443},
				AuthBySAToken: true,
			},
		}
		httpsEndpoints1 = []CheckHTTPSEndpoint{
			{Endpoint: config.Endpoint{Hostname: "server", IP: "", Port: 55555}},
			{Endpoint: config.Endpoint{Hostname: "server2", IP: "", Port: 443}},
		}
		httpsEndpointsInternalKubeAPIServer = []CheckHTTPSEndpoint{
			{
				Endpoint:      config.Endpoint{Hostname: common.DomainNameKubernetesService, IP: "", Port: 443},
				AuthBySAToken: true,
			},
		}
		dnsnames = []string{
			"eu.gcr.io.", "foo.bar.", common.DomainNameKubernetesService, "api.shoot.domain.com.",
		}
	)

	BeforeEach(func() {
		_ = os.Setenv("KUBERNETES_SERVICE_HOST", "api.shoot.domain.com")
	})

	DescribeTable("should parse runner commands",
		func(clusterCfg config.ClusterConfig, runnerConfig RunnerConfig, args []string, expected interface{}) {
			actual, err := Parse(clusterCfg, runnerConfig, args, &config.SampleConfig{})
			switch v := expected.(type) {
			case Runner:
				Expect(err).To(BeNil())
				Expect(actual.Config()).To(Equal(v.Config()))
				Expect(actual.runner.TestData()).To(Equal(v.TestData()))
			case string:
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(ContainSubstring(v))
			default:
				Fail("unexpected type")
			}
		},

		Entry("pingHost", clusterCfg1, config1,
			[]string{"pingHost"}, NewPingHost(clusterCfg1.Nodes, config1)),
		Entry("pingHost with hosts and custom period", clusterCfg1, config1,
			[]string{"pingHost", "--period", "10s", "--hosts", "node3:10.0.0.13,node4:10.0.0.14"}, NewPingHost(clusterCfg2.Nodes, config2)),
		Entry("pingHost - invalid option", clusterCfg1, config1,
			[]string{"pingHost", "--foo"}, "unknown flag: --foo"),
		Entry("pingHost - invalid host", clusterCfg1, config1,
			[]string{"pingHost", "--hosts", "node3"}, "invalid host node3"),
		Entry("checkTCPPort", clusterCfg1, config1,
			[]string{"checkTCPPort", "--period", "10s", "--endpoints", "server:10.0.0.9:55555"}, NewCheckTCPPort(endpoints1, config2)),
		Entry("checkTCPPort - missing endpoints", clusterCfg1, config1,
			[]string{"checkTCPPort"}, "no endpoints"),
		Entry("checkTCPPort - invalid endpoint", clusterCfg1, config1,
			[]string{"checkTCPPort", "--endpoints", "server:10.0.0.9:x"}, "invalid endpoint port x"),
		Entry("checkTCPPort with node port", clusterCfg1, config1,
			[]string{"checkTCPPort", "--node-port", "55555"}, NewCheckTCPPort(endpoints2, config1)),
		Entry("checkTCPPort with pod endpoints", clusterCfg1, config1,
			[]string{"checkTCPPort", "--endpoints-of-pod-ds"}, NewCheckTCPPort(endpointsPods, config1)),
		Entry("checkTCPPort with internal kube-apiserver endpoints", clusterCfg1, config1,
			[]string{"checkTCPPort", "--endpoint-internal-kube-apiserver"}, NewCheckTCPPort(endpointsInternalKubeAPIServer, config1)),
		Entry("checkTCPPort with external kube-apiserver endpoints", clusterCfg1, config1,
			[]string{"checkTCPPort", "--endpoint-external-kube-apiserver"}, NewCheckTCPPort(endpointsKubeAPIServer, config1)),
		Entry("checkHTTPSGet", clusterCfg1, config1,
			[]string{"checkHTTPSGet", "--period", "10s", "--endpoints", "server:55555,server2"}, NewCheckHTTPSGet(httpsEndpoints1, config2)),
		Entry("checkHTTPSGet - missing endpoints", clusterCfg1, config1,
			[]string{"checkHTTPSGet"}, "no endpoints"),
		Entry("checkHTTPSGet - invalid endpoint", clusterCfg1, config1,
			[]string{"checkHTTPSGet", "--endpoints", "server:x"}, "invalid endpoint port x"),
		Entry("checkHTTPSGet with internal kube-apiserver endpoints", clusterCfg1, config1,
			[]string{"checkHTTPSGet", "--endpoint-internal-kube-apiserver"}, NewCheckHTTPSGet(httpsEndpointsInternalKubeAPIServer, config1)),
		Entry("checkHTTPSGet with external kube-apiserver endpoints", clusterCfg1, config1,
			[]string{"checkHTTPSGet", "--endpoint-external-kube-apiserver"}, NewCheckHTTPSGet(httpsEndpointsKubeAPIServer, config1)),
		Entry("nslookup with host names", clusterCfg1, config1,
			[]string{"nslookup", "--names", "eu.gcr.io,foo.bar.", "--name-internal-kube-apiserver", "--name-external-kube-apiserver"},
			NewNSLookup(dnsnames, config1)),
	)
})
