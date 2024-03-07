// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package deploy_test

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/deploy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Add default seccomp profile when enabled", func() {
	var deployConfig *deploy.AgentDeployConfig

	BeforeEach(func() {
		deployConfig = &deploy.AgentDeployConfig{
			Image:         "image:tag",
			DefaultPeriod: 16 * time.Second,
			PingEnabled:   false,
		}
	})

	It("should create daemonset without seccomp profile", func() {
		objs, err := deploy.NetworkProblemDetectorAgent(deployConfig)
		Expect(err).To(BeNil())
		Expect(len(objs)).NotTo(BeZero())
		var ds *appsv1.DaemonSet
		for _, obj := range objs {
			switch v := obj.(type) {
			case *appsv1.DaemonSet:
				ds = v
			}
		}

		Expect(ds).NotTo(BeNil())
		Expect(ds.Spec.Template.Spec.SecurityContext).To(BeNil())
	})

	It("should create daemonset with seccomp profile", func() {
		deployConfig.DefaultSeccompProfileEnabled = true
		objs, err := deploy.NetworkProblemDetectorAgent(deployConfig)
		Expect(err).To(BeNil())
		Expect(len(objs)).NotTo(BeZero())
		var ds *appsv1.DaemonSet
		for _, obj := range objs {
			switch v := obj.(type) {
			case *appsv1.DaemonSet:
				ds = v
			}
		}

		Expect(ds).NotTo(BeNil())
		Expect(ds.Spec.Template.Spec.SecurityContext).NotTo(BeNil())
		Expect(ds.Spec.Template.Spec.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
	})
})
