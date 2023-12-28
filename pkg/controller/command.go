// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"

	"github.com/gardener/network-problem-detector/pkg/common"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	// leaderElectionID is the name of the lease resource.
	leaderElectionID = "network-problem-detector-controller-leader-election"
)

type controllerCommand struct {
	common.ClientsetBase

	healthzPort int
	metricsPort int

	leaderElection          bool
	leaderElectionNamespace string
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

func (cc *controllerCommand) runController(_ *cobra.Command, _ []string) error {
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
		LeaderElectionID:           leaderElectionID,
		LeaderElectionNamespace:    cc.leaderElectionNamespace,
		Metrics: server.Options{
			BindAddress: metricsBindAddress,
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", cc.healthzPort),
	}
	mgr, err := manager.New(config, options)
	if err != nil {
		log.Error(err, "could not create manager")
		return err
	}

	if err := cc.SetupClientSet(); err != nil {
		return err
	}

	watcher := &watch{log: log, clientSet: cc.Clientset}
	if err := mgr.Add(watcher); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("nwpd-controller", watcher.healthzCheck); err != nil {
		return err
	}
	ctx := signals.SetupSignalHandler()
	return mgr.Start(ctx)
}
