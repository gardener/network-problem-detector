// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.uber.org/atomic"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

const (
	// leaderElectionId is the name of the lease resource
	leaderElectionId = "network-problem-detector-controller-leader-election"
)

type controllerCommand struct {
	common.ClientsetBase

	healthzPort int
	metricsPort int

	leaderElection          bool
	leaderElectionNamespace string

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
	cmd.Flags().IntVar(&cc.metricsPort, "metrics-port", 0, "port for metrics")
	cmd.Flags().IntVar(&cc.healthzPort, "health-probe-port", 8081, "port for health probes")
	cmd.Flags().BoolVar(&cc.leaderElection, "leader-election", false, "enable leader election")
	cmd.Flags().StringVar(&cc.leaderElectionNamespace, "leader-election-namespace", "kube-system", "namespace for the lease resource")

	return cmd
}

func (cc *controllerCommand) runController(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "controller")

	config, err := cc.RestConfig()
	if err != nil {
		return err
	}
	metricsBindAddress := "0" // disabled
	if cc.metricsPort != 0 {
		metricsBindAddress = fmt.Sprintf(":%d", cc.metricsPort)
		log.Infof("metrics at :%d/metrics", cc.metricsPort)
	}
	log.Infof("health probe at :%d/healthz", cc.healthzPort)
	options := manager.Options{
		LeaderElection:             cc.leaderElection,
		LeaderElectionResourceLock: resourcelock.LeasesResourceLock,
		LeaderElectionID:           leaderElectionId,
		LeaderElectionNamespace:    cc.leaderElectionNamespace,
		MetricsBindAddress:         metricsBindAddress,
		HealthProbeBindAddress:     fmt.Sprintf(":%d", cc.healthzPort),
	}
	mgr, err := manager.New(config, options)
	if err != nil {
		log.Error(err, "could not create manager")
		return err
	}

	mgr.AddHealthzCheck("nwpd-controller", cc.healthzCheck)
	mgr.Add(&watch{log: log, cc: cc})
	ctx := signals.SetupSignalHandler()
	return mgr.Start(ctx)
}

func (cc *controllerCommand) healthzCheck(req *http.Request) error {
	if time.Now().UnixMilli()-cc.lastLoop.Load() > 30000 {
		return fmt.Errorf("no successful loop since %s", time.UnixMilli(cc.lastLoop.Load()))
	}
	return nil
}
