// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"

	"github.com/gardener/network-problem-detector/pkg/agent/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	agentConfigFile   string
	clusterConfigFile string
	hostNetwork       bool
)

func CreateRunAgentCmd(injectedVersion string) *cobra.Command {
	version.Version = injectedVersion
	cmd := &cobra.Command{
		Use:   "run-agent",
		Short: "runs agent server",
		Long:  `The agent runs in a pod either on the host network or the pod network`,
	}
	cmd.Flags().StringVar(&agentConfigFile, "config", "agent.config", "file configuration of agent server.")
	cmd.Flags().StringVar(&clusterConfigFile, "cluster-config", "cluster.config", "file configuration of cluster nodes and agent pods.")
	cmd.Flags().BoolVar(&hostNetwork, "hostNetwork", false, "if agent runs on host network.")
	cmd.RunE = runAgent
	return cmd
}

func runAgent(cmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "agent")

	if agentConfigFile == "" {
		return fmt.Errorf("Missing --config option")
	}
	if clusterConfigFile == "" {
		return fmt.Errorf("Missing --cluster-config option")
	}

	srv, err := startAgentServer(log, agentConfigFile, clusterConfigFile, hostNetwork)
	if err != nil {
		return fmt.Errorf("cannot start server: %w", err)
	}

	log.Info("running...")
	srv.run()
	return nil
}

func startAgentServer(log logrus.FieldLogger, agentConfigFile, clusterConfigFile string, hostNetwork bool) (*server, error) {
	agentServer, err := newServer(log, agentConfigFile, clusterConfigFile, hostNetwork)
	if err != nil {
		return nil, err
	}

	err = agentServer.setup()
	if err != nil {
		return nil, err
	}

	return agentServer, nil
}
