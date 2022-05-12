// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"os"

	"github.com/gardener/network-problem-detector/pkg/common"
)

func GetNodeName() string {
	nodeName := os.Getenv(common.EnvNodeName)
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	return nodeName
}
