// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRunners(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Runners Suite")
}
