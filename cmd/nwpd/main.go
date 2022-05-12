// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/gardener/network-problem-detector/pkg/agent"
	"github.com/gardener/network-problem-detector/pkg/aggregate"
	"github.com/gardener/network-problem-detector/pkg/collect"
	"github.com/gardener/network-problem-detector/pkg/deploy"
	"github.com/gardener/network-problem-detector/pkg/list"
	"github.com/gardener/network-problem-detector/pkg/query"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "nwpdcli",
		Short: "Network problem detector client and agent",
	}
)

func main() {
	rootCmd.AddCommand(agent.CreateRunAgentCmd())
	rootCmd.AddCommand(deploy.CreateDeployCmd())
	rootCmd.AddCommand(collect.CreateCollectCmd())
	rootCmd.AddCommand(aggregate.CreateAggregateCmd())
	rootCmd.AddCommand(query.CreateQueryCmd())
	rootCmd.AddCommand(list.CreateListCmd())
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
