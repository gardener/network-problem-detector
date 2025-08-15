// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"
)

var _ = Describe("utils", func() {
	clusterCfg := config.ClusterConfig{
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

	It("should parse cluster config properly", func() {
		data, err := yaml.Marshal(clusterCfg)
		Expect(err).NotTo(HaveOccurred())

		file, err := os.CreateTemp("", "test-cluster-config-")
		defer os.Remove(file.Name())
		Expect(err).NotTo(HaveOccurred())

		err = os.WriteFile(file.Name(), data, 0o644)
		Expect(err).NotTo(HaveOccurred())

		cfg, err := config.LoadClusterConfig(file.Name())
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.InternalKubeAPIServer).To(Equal(clusterCfg.InternalKubeAPIServer))
		Expect(cfg.KubeAPIServer).To(Equal(clusterCfg.KubeAPIServer))
	})

	It("should remove token file from cluster config during parsing", func() {
		tokenConfig := config.ClusterConfig{
			InternalKubeAPIServer: &config.Endpoint{
				Hostname:  clusterCfg.InternalKubeAPIServer.Hostname,
				IP:        clusterCfg.InternalKubeAPIServer.IP,
				Port:      clusterCfg.InternalKubeAPIServer.Port,
				TokenFile: "internal-token-file",
			},
			KubeAPIServer: &config.Endpoint{
				Hostname:  clusterCfg.KubeAPIServer.Hostname,
				IP:        clusterCfg.KubeAPIServer.IP,
				Port:      clusterCfg.KubeAPIServer.Port,
				TokenFile: "external-token-file",
			},
		}
		data, err := yaml.Marshal(tokenConfig)
		Expect(err).NotTo(HaveOccurred())

		file, err := os.CreateTemp("", "test-cluster-config-")
		defer os.Remove(file.Name())
		Expect(err).NotTo(HaveOccurred())

		err = os.WriteFile(file.Name(), data, 0o644)
		Expect(err).NotTo(HaveOccurred())

		cfg, err := config.LoadClusterConfig(file.Name())
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.InternalKubeAPIServer).NotTo(Equal(tokenConfig.InternalKubeAPIServer))
		Expect(cfg.InternalKubeAPIServer).To(Equal(clusterCfg.InternalKubeAPIServer))
		Expect(cfg.KubeAPIServer).NotTo(Equal(tokenConfig.KubeAPIServer))
		Expect(cfg.KubeAPIServer).To(Equal(clusterCfg.KubeAPIServer))
	})
})
