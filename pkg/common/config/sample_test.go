// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"fmt"
	"math"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const nodeCount = 100
const maxNodes = 20

var _ = Describe("sample", func() {
	var nodes []config.Node
	var podEndpoints []config.PodEndpoint
	var nodes2 []config.Node
	var podEndpoints2 []config.PodEndpoint
	for i := 0; i < nodeCount; i++ {
		hostname := fmt.Sprintf("host-%d", i)
		nodes = append(nodes, config.Node{Hostname: hostname, InternalIP: fmt.Sprintf("10.0.0.%d", i+10)})
		podEndpoints = append(podEndpoints, config.PodEndpoint{Nodename: hostname, Podname: fmt.Sprintf("pod%d", i), PodIP: fmt.Sprintf("10.128.0.%d", i+10), Port: 1234})
		j := i
		if shouldReplaceNode(i) {
			j = i + nodeCount
		}
		hostname = fmt.Sprintf("host-%d", j)
		nodes2 = append(nodes2, config.Node{Hostname: hostname, InternalIP: fmt.Sprintf("10.0.0.%d", j+10)})
		podEndpoints2 = append(podEndpoints2, config.PodEndpoint{Nodename: hostname, Podname: fmt.Sprintf("pod%d", j), PodIP: fmt.Sprintf("10.128.0.%d", j+10), Port: 1234})
	}

	clusterCfg := config.ClusterConfig{
		Nodes:        nodes,
		PodEndpoints: podEndpoints,
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

	clusterCfg2 := config.ClusterConfig{
		Nodes:        nodes2,
		PodEndpoints: podEndpoints2,
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

	It("should select all nodes if maxNodes == 0", func() {
		sc := &config.SampleConfig{
			MaxNodes:        0,
			NodeSampleStore: config.NewNodeSampleStore(),
		}

		shuffledCC := sc.ShuffledSample(clusterCfg)
		Expect(len(shuffledCC.Nodes)).To(Equal(nodeCount))
		Expect(len(shuffledCC.PodEndpoints)).To(Equal(nodeCount))
	})

	It("should select good distributed, random sample if maxNodes > 0", func() {
		scList := make([]*config.SampleConfig, nodeCount)
		ccList := make([]config.ClusterConfig, nodeCount)
		for i := 0; i < nodeCount; i++ {
			scList[i] = &config.SampleConfig{
				MaxNodes:        maxNodes,
				NodeSampleStore: config.NewNodeSampleStore(),
			}
			ccList[i] = scList[i].ShuffledSample(clusterCfg)
		}

		distribution, total := calcNodeDistribution(ccList)
		Expect(total).To(Equal(nodeCount * maxNodes))
		Expect(goodDistribution(nodeCount, maxNodes, distribution)).To(BeTrue())

		By("keeps node selection stable")
		ccList2 := make([]config.ClusterConfig, nodeCount)
		sumDelta := 0
		for i := 0; i < nodeCount; i++ {
			if shouldReplaceNode(i) {
				scList[i] = &config.SampleConfig{
					MaxNodes:        maxNodes,
					NodeSampleStore: config.NewNodeSampleStore(),
				}
			}
			ccList2[i] = scList[i].ShuffledSample(clusterCfg2)
			sumDelta += calcDelta(ccList[i].Nodes, ccList2[i].Nodes)
		}
		distribution, total = calcNodeDistribution(ccList2)
		Expect(total).To(Equal(nodeCount * maxNodes))
		Expect(goodDistribution(nodeCount, maxNodes, distribution)).To(BeTrue())
		mismatchNodeCount := nodeCount / 17
		Expect(sumDelta > (mismatchNodeCount-1)*nodeCount && sumDelta < (mismatchNodeCount+1)*nodeCount).To(BeTrue(), fmt.Sprintf("Unexpected delta: %d (%d)", sumDelta, mismatchNodeCount*nodeCount))
	})
})

func calcDelta(nodes1, nodes2 []config.Node) int {
	counts := map[string]int{}

	for _, node := range nodes1 {
		counts[node.DestHost()]++
	}
	for _, node := range nodes2 {
		counts[node.DestHost()]++
	}

	delta := 0
	for _, count := range counts {
		if count != 2 {
			delta++
		}
	}
	return delta
}

func calcNodeDistribution(ccList []config.ClusterConfig) (map[int]int, int) {
	nodeCounters := map[string]int{}
	total := 0
	for _, list := range ccList {
		for _, node := range list.Nodes {
			nodeCounters[node.Hostname]++
			total++
		}
	}

	distribution := map[int]int{}
	for _, count := range nodeCounters {
		distribution[count]++
	}
	return distribution, total
}

func goodDistribution(N, K int, distribution map[int]int) bool {
	println(fmt.Sprintf("%v", distribution))
	var a, b, c, d int
	for k, count := range distribution {
		a += count
		b += k * count
		if math.Abs(float64(k-K)) <= float64(K/2) {
			c += count
		} else {
			d += count
		}
	}
	//println(float64(b)/float64(a), a, b, float64(c)/float64(a), float64(d)/float64(a))
	return float64(d)/float64(a) < 0.1
}

func shouldReplaceNode(i int) bool {
	return i%17 == 0
}
