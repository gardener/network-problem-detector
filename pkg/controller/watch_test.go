// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("apiServerAddressChanged", func() {
	var w *watch

	BeforeEach(func() {
		w = &watch{log: logr.Discard()}
	})

	It("reports a change when shoot info is missing", func() {
		Expect(w.apiServerAddressChanged(nil, nil)).To(BeTrue())
	})

	It("does not panic and reports a change when the cached endpoint is nil", func() {
		// The cached endpoint is nil after a previous DNS lookup failure.
		shootInfo := &corev1.ConfigMap{Data: map[string]string{"domain": "localhost"}}
		Expect(func() {
			Expect(w.apiServerAddressChanged(shootInfo, nil)).To(BeTrue())
		}).NotTo(Panic())
	})
})
