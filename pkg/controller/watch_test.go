// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/yaml"

	"github.com/gardener/network-problem-detector/pkg/common/config"
)

func apiServerEndpoint(ip string) *config.Endpoint {
	return &config.Endpoint{Hostname: "api.shoot.example.com", IP: ip, Port: 443}
}

var _ = Describe("watch", func() {
	var (
		clientSet *fake.Clientset
		fakeClock *clocktesting.FakeClock
		ctx       context.Context
		cancel    context.CancelFunc
		done      chan struct{}
	)

	BeforeEach(func() {
		clientSet = fake.NewClientset(
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kubernetes"},
				Spec: corev1.ServiceSpec{
					ClusterIP: "100.64.0.1",
					Ports:     []corev1.ServicePort{{Port: 443}},
				},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "shoot-info"},
				Data: map[string]string{
					"domain":       "shoot.example.com",
					"nodeNetworks": "10.250.0.0/16",
				},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "network-problem-detector-cluster-config"},
				Data:       map[string]string{"cluster-config.yaml": ""},
			},
		)
		fakeClock = clocktesting.NewFakeClock(time.Now())
		ctx, cancel = context.WithCancel(context.Background())
		done = nil
	})

	AfterEach(func() {
		cancel()
		if done != nil {
			fakeClock.Step(10 * time.Second)
			Eventually(done).Should(BeClosed())
		}
	})

	start := func(w *watch) {
		done = make(chan struct{})
		go func() {
			defer close(done)
			defer GinkgoRecover()
			_ = w.Start(ctx)
		}()
	}

	clusterConfigAPIServer := func() *config.Endpoint {
		cm, err := clientSet.CoreV1().ConfigMaps("kube-system").Get(ctx, "network-problem-detector-cluster-config", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		cfg := &config.ClusterConfig{}
		Expect(yaml.Unmarshal([]byte(cm.Data["cluster-config.yaml"]), cfg)).To(Succeed())
		return cfg.KubeAPIServer
	}

	It("recovers when API server DNS resolution fails and then succeeds", func() {
		var calls atomic.Int32
		lookupFailed := make(chan struct{}, 1)
		w := &watch{
			log: funcr.New(func(_, message string) {
				if strings.Contains(message, "fetching kube-apiserver external endpoint failed") {
					lookupFailed <- struct{}{}
				}
			}, funcr.Options{}),
			clientSet: clientSet,
			clock:     fakeClock,
			resolveAPIServer: func(_ *corev1.ConfigMap) (*config.Endpoint, error) {
				if calls.Add(1) == 1 {
					return nil, fmt.Errorf("lookup api.shoot.example.com: no such host")
				}
				return apiServerEndpoint("203.0.113.10"), nil
			},
		}
		start(w)

		By("failing DNS resolution in the first iteration")
		// Once the error is logged, this iteration skips the ConfigMap update.
		Eventually(lookupFailed).Should(Receive())
		Expect(calls.Load()).To(BeEquivalentTo(1))
		Expect(clusterConfigAPIServer()).To(BeNil())

		By("succeeding DNS resolution in the second iteration")
		fakeClock.Step(10 * time.Second)
		Eventually(clusterConfigAPIServer).Should(Equal(apiServerEndpoint("203.0.113.10")))
		Expect(calls.Load()).To(BeEquivalentTo(2))

		By("comparing against the cached endpoint in the third iteration")
		fakeClock.Step(10 * time.Second)
		Eventually(w.lastLoop.Load).Should(Equal(fakeClock.Now().UnixMilli()))
		Expect(calls.Load()).To(BeEquivalentTo(3))
		Expect(done).NotTo(BeClosed())
	})

	It("updates the cluster config when the API server IP changes", func() {
		var ip atomic.Value
		ip.Store("203.0.113.10")
		w := &watch{
			log:       logr.Discard(),
			clientSet: clientSet,
			clock:     fakeClock,
			resolveAPIServer: func(_ *corev1.ConfigMap) (*config.Endpoint, error) {
				return apiServerEndpoint(ip.Load().(string)), nil
			},
		}
		start(w)

		Eventually(clusterConfigAPIServer).Should(Equal(apiServerEndpoint("203.0.113.10")))

		ip.Store("203.0.113.20")
		fakeClock.Step(10 * time.Second)
		Eventually(clusterConfigAPIServer).Should(Equal(apiServerEndpoint("203.0.113.20")))
	})

	It("does not run another iteration before the loop interval has passed", func() {
		var calls atomic.Int32
		w := &watch{
			log:       logr.Discard(),
			clientSet: clientSet,
			clock:     fakeClock,
			resolveAPIServer: func(_ *corev1.ConfigMap) (*config.Endpoint, error) {
				calls.Add(1)
				return apiServerEndpoint("203.0.113.10"), nil
			},
		}
		start(w)

		Eventually(clusterConfigAPIServer).Should(Equal(apiServerEndpoint("203.0.113.10")))
		fakeClock.Step(9 * time.Second)
		Consistently(calls.Load, 200*time.Millisecond).Should(BeEquivalentTo(1))

		fakeClock.Step(1 * time.Second)
		Eventually(calls.Load).Should(BeEquivalentTo(2))
	})
})

var _ = Describe("apiServerAddressChanged", func() {
	It("reports a change without resolving when the cached endpoint is nil", func() {
		var calls atomic.Int32
		w := &watch{
			log: logr.Discard(),
			resolveAPIServer: func(_ *corev1.ConfigMap) (*config.Endpoint, error) {
				calls.Add(1)
				return apiServerEndpoint("203.0.113.10"), nil
			},
		}
		shootInfo := &corev1.ConfigMap{Data: map[string]string{"domain": "shoot.example.com"}}
		Expect(w.apiServerAddressChanged(shootInfo, nil)).To(BeTrue())
		Expect(calls.Load()).To(BeZero())
	})
})
