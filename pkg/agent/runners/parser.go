// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/spf13/cobra"
)

type runnerArgs struct {
	args       []string
	clusterCfg nwpd.ClusterConfig
	config     nwpd.RunnerConfig
	period     time.Duration

	runner nwpd.Runner
}

func GetNewRoot(ra *runnerArgs) *cobra.Command {
	root := &cobra.Command{
		Use:   "runner",
		Short: "internal runner commands",
	}
	root.PersistentFlags().DurationVar(&ra.period, "period", 0, "overwrites default execution period")
	root.AddCommand(createPingHostCmd(ra))
	root.AddCommand(createCheckTCPPortCmd(ra))
	root.AddCommand(createDiscoverMDNSCmd(ra))
	return root
}

func Parse(clusterCfg nwpd.ClusterConfig, config nwpd.RunnerConfig, args []string, shuffle bool) (nwpd.Runner, error) {
	ra := &runnerArgs{}
	root := GetNewRoot(ra)

	cmd, flags, err := root.Find(args)
	if err != nil {
		return nil, err
	}

	err = cmd.ParseFlags(flags)
	if err != nil {
		return nil, cmd.FlagErrorFunc()(cmd, err)
	}

	ra.args = args
	ra.clusterCfg = clusterCfg
	if shuffle {
		ra.clusterCfg = clusterCfg.Shuffled()
	}
	ra.config = config
	ra.runner = nil
	err = cmd.RunE(cmd, flags)
	if err != nil {
		return nil, err
	}
	return ra.runner, nil
}
