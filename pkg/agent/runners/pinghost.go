// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"fmt"
	"strings"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"

	"github.com/go-ping/ping"
	"github.com/spf13/cobra"
	"go.uber.org/atomic"
)

type pingHostArgs struct {
	runnerArgs *runnerArgs
	hosts      []string
}

func (a *pingHostArgs) createRunner(_ *cobra.Command, _ []string) error {
	var nodes []config.Node
	if len(a.hosts) > 0 {
		for _, host := range a.hosts {
			parts := strings.SplitN(host, ":", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid job: %s: invalid host %s", strings.Join(a.runnerArgs.args, " "), host)
			}
			nodes = append(nodes, config.Node{
				Hostname:   parts[0],
				InternalIP: parts[1],
			})
		}
	} else {
		nodes = a.runnerArgs.clusterCfg.Nodes
	}

	config := a.runnerArgs.prepareConfig()
	if r := NewPingHost(nodes, config); r != nil {
		a.runnerArgs.runner = r
	}
	return nil
}

func createPingHostCmd(ra *runnerArgs) *cobra.Command {
	a := &pingHostArgs{runnerArgs: ra}
	cmd := &cobra.Command{
		Use:   "pingHost",
		Short: "pings a hostname",
		RunE:  a.createRunner,
	}
	cmd.Flags().StringSliceVar(&a.hosts, "hosts", nil, "Optional hosts in format <hostname>:<ip>. If not specified, the nodelist is used.")
	return cmd
}

func NewPingHost(nodes []config.Node, rconfig RunnerConfig) Runner {
	if len(nodes) == 0 {
		return nil
	}
	return &pingHost{
		robinRound[config.Node]{
			itemsName: "nodes",
			items:     config.CloneAndShuffle(nodes),
			runFunc:   pingFunc,
			config:    rconfig,
		},
	}
}

type pingHost struct {
	robinRound[config.Node]
}

var _ Runner = &pingHost{}

func pingFunc(node config.Node) (string, error) {
	pinger, err := ping.NewPinger(node.InternalIP)
	if err != nil {
		return "", err
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = 1 * time.Second

	result := atomic.String{}
	pinger.OnRecv = func(pkt *ping.Packet) {
		result.Store(fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt))
	}

	pinger.OnDuplicateRecv = func(pkt *ping.Packet) {
		result.Store(fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl))
	}

	err = pinger.Run()
	if err != nil {
		return "", err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 1 {
		return result.Load(), nil
	}
	return "", fmt.Errorf("ping lost after %d ms", pinger.Timeout.Milliseconds())
}
