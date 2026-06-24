/*
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package common

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

// NewLogger builds a production logger and binds the cmd field.
func NewLogger(cmd string) logr.Logger {
	zapLog, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	return zapr.NewLogger(zapLog).WithValues("cmd", cmd)
}
