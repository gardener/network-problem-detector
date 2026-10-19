// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("checkHTTPSGet", func() {
	It("should not leak connections", func() {
		var opened, closed atomic.Int32
		// The response body is never read by the check. Since Go 1.27, closing an unread body drains it,
		// which makes the connection reusable and keeps it in the idle pool of the discarded transport.
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 512)))
		}))
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				opened.Add(1)
			case http.StateClosed, http.StateHijacked:
				closed.Add(1)
			}
		}
		server.StartTLS()
		defer server.Close()

		u, err := url.Parse(server.URL)
		Expect(err).NotTo(HaveOccurred())
		port, err := strconv.Atoi(u.Port())
		Expect(err).NotTo(HaveOccurred())
		endpoint := CheckHTTPSEndpoint{Endpoint: config.Endpoint{Hostname: u.Hostname(), Port: port}}

		const checks = 5
		for range checks {
			status, err := checkHTTPSGetFunc(endpoint)
			Expect(err).NotTo(HaveOccurred())
			Expect(status).To(Equal("200 OK"))
		}

		Expect(opened.Load()).To(BeEquivalentTo(checks))
		Eventually(closed.Load).WithTimeout(5 * time.Second).Should(BeEquivalentTo(checks))
	})
})
