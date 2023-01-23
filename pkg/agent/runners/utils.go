// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"strings"
)

func normalise(dnsname string) string {
	if strings.HasSuffix(dnsname, ".") {
		return dnsname[:len(dnsname)-1]
	}
	return dnsname
}

func fullQualified(dnsname string) string {
	if !strings.HasSuffix(dnsname, ".") {
		return dnsname + "."
	}
	return dnsname
}
