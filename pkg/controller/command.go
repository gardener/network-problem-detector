// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/atomic"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type controllerCommand struct {
	common.ClientsetBase
	httpPort int

	lastLoop atomic.Int64
}

func CreateRunControllerCmd() *cobra.Command {
	cc := &controllerCommand{}
	cmd := &cobra.Command{
		Use:   "run-controller",
		Short: "runs agent controller",
		Long:  "The agent controller watches nodes and pods to adjust configmap",
		RunE:  cc.runController,
	}
	cc.AddKubeConfigFlag(cmd.Flags())
	cc.AddInClusterFlag(cmd.Flags())
	cmd.Flags().IntVar(&cc.httpPort, "http-port", 0, "if != 0, starts http server for metrics and healthz checks.")

	return cmd
}

func (cc *controllerCommand) runController(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "controller")

	if cc.httpPort != 0 {
		log.Infof("provide metrics at ':%d/metrics'", cc.httpPort)
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/healthz", cc.healthzHandler)
		go func() {
			http.ListenAndServe(fmt.Sprintf(":%d", cc.httpPort), nil)
		}()
	}

	return cc.watch(log)
}

func (cc *controllerCommand) healthzHandler(w http.ResponseWriter, req *http.Request) {
	if time.Now().UnixMilli()-cc.lastLoop.Load() > 30000 {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("no successful loop since %s", time.UnixMilli(cc.lastLoop.Load()))))
	} else {
		w.Write([]byte("ok"))
	}
}
