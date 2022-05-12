// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"fmt"
	"strings"

	"github/gardener/network-problem-detector/pkg/common"
	"github/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/hashicorp/mdns"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type discoverMDNSArgs struct {
	runnerArgs *runnerArgs
}

func (a *discoverMDNSArgs) createRunner(cmd *cobra.Command, args []string) error {
	config := a.runnerArgs.config
	if a.runnerArgs.period != 0 {
		config.Period = a.runnerArgs.period
	}
	a.runnerArgs.runner = NewDiscoverMDNS(config)
	return nil
}

func createDiscoverMDNSCmd(ra *runnerArgs) *cobra.Command {
	a := &discoverMDNSArgs{runnerArgs: ra}
	cmd := &cobra.Command{
		Use:   "discoverMDNS",
		Short: "discover mDNS services",
		RunE:  a.createRunner,
	}
	return cmd
}

func NewDiscoverMDNS(config nwpd.RunnerConfig) *discoverMDNS {
	return &discoverMDNS{
		config: config,
	}
}

type discoverMDNS struct {
	config nwpd.RunnerConfig
}

var _ nwpd.Runner = &discoverMDNS{}

func (r *discoverMDNS) Config() nwpd.RunnerConfig {
	return r.config
}

func (r *discoverMDNS) Run(ch chan<- *nwpd.Observation) {
	nodeName := GetNodeName()

	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	go func() {
		for entry := range entriesCh {
			if entry.Host != "" {
				obs := &nwpd.Observation{
					SrcHost:   nodeName,
					DestHost:  normalise(entry.Host),
					Result:    fmt.Sprintf("%s:%d (%s)", entry.Name, entry.Port, entry.AddrV4.String()),
					Timestamp: timestamppb.Now(),
					JobID:     r.config.JobID,
					Ok:        true,
				}
				ch <- obs
			}
		}
	}()

	// Start the lookup
	params := mdns.DefaultParams(common.MDNSServiceNodeNetAgent)
	params.DisableIPv6 = true
	params.Entries = entriesCh
	err := mdns.Query(params)
	if err != nil {
		obs := &nwpd.Observation{
			SrcHost:   nodeName,
			Result:    err.Error(),
			Timestamp: timestamppb.Now(),
			JobID:     r.config.JobID,
			Ok:        false,
		}
		ch <- obs
	}
	close(entriesCh)
}

func normalise(dnsname string) string {
	if strings.HasSuffix(dnsname, ".") {
		return dnsname[:len(dnsname)-1]
	}
	return dnsname
}
