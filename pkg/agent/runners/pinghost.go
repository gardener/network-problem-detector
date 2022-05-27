// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"fmt"
	"strings"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/go-ping/ping"
	"github.com/spf13/cobra"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type pingHostArgs struct {
	runnerArgs *runnerArgs
	hosts      []string
}

func (a *pingHostArgs) createRunner(cmd *cobra.Command, args []string) error {
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

func NewPingHost(nodes []config.Node, rconfig RunnerConfig) *pingHost {
	if len(nodes) == 0 {
		return nil
	}
	return &pingHost{
		nodes:  config.CloneAndShuffle(nodes),
		config: rconfig,
	}
}

type pingHost struct {
	nodes  []config.Node
	next   int
	config RunnerConfig
}

var _ Runner = &pingHost{}

func (r *pingHost) Config() RunnerConfig {
	return r.config
}

func (r *pingHost) Description() string {
	return fmt.Sprintf("%d hosts", len(r.nodes))
}

func (r *pingHost) Run(ch chan<- *nwpd.Observation) {
	node := r.nodes[r.next]
	r.next = (r.next + 1) % len(r.nodes)

	nodeName := GetNodeName()
	obs := &nwpd.Observation{
		SrcHost:   nodeName,
		DestHost:  node.Hostname,
		Timestamp: timestamppb.Now(),
		JobID:     r.config.JobID,
	}

	result, d, err := r.ping(node)
	obs.Duration = durationpb.New(d)
	obs.Ok = err == nil
	if err != nil {
		obs.Result = fmt.Sprintf("error: %s", err)
	} else {
		obs.Result = result
	}
	ch <- obs
}

func (r *pingHost) ping(node config.Node) (string, time.Duration, error) {
	pinger, err := ping.NewPinger(node.InternalIP)
	if err != nil {
		return "", 0, err
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
		return "", 0, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 1 {
		return result.Load(), stats.AvgRtt, nil
	}
	return "", stats.AvgRtt, fmt.Errorf("ping lost after %d ms", pinger.Timeout.Milliseconds())
}
