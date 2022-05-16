// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type checkTCPPortArgs struct {
	runnerArgs   *runnerArgs
	nodePort     int
	podDS        bool
	internalKAPI bool
	externalKAPI bool
	endpoints    []string
}

func (a *checkTCPPortArgs) createRunner(cmd *cobra.Command, args []string) error {
	allowEmpty := false
	var endpoints []config.Endpoint
	if len(a.endpoints) > 0 {
		for _, ep := range a.endpoints {
			parts := strings.SplitN(ep, ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("invalid endpoint %s", ep)
			}
			port, err := strconv.Atoi(parts[2])
			if err != nil {
				return fmt.Errorf("invalid endpoint port %s", parts[2])
			}
			endpoints = append(endpoints, config.Endpoint{
				Hostname: parts[0],
				IP:       parts[1],
				Port:     port,
			})
		}
	} else if a.nodePort != 0 {
		allowEmpty = true
		for _, n := range a.runnerArgs.clusterCfg.Nodes {
			endpoints = append(endpoints, config.Endpoint{
				Hostname: n.Hostname,
				IP:       n.InternalIP,
				Port:     a.nodePort,
			})
		}
	} else if a.podDS {
		allowEmpty = true
		for _, pe := range a.runnerArgs.clusterCfg.PodEndpoints {
			endpoints = append(endpoints, config.Endpoint{
				Hostname: pe.Nodename,
				IP:       pe.PodIP,
				Port:     int(pe.Port),
			})
		}
	} else if a.internalKAPI {
		allowEmpty = true
		if pe := a.runnerArgs.clusterCfg.InternalKubeAPIServer; pe != nil {
			endpoints = append(endpoints, *pe)
		}
	} else if a.externalKAPI {
		allowEmpty = true
		if pe := a.runnerArgs.clusterCfg.KubeAPIServer; pe != nil {
			endpoints = append(endpoints, *pe)
		}
	}

	if !allowEmpty && len(endpoints) == 0 {
		return fmt.Errorf("no endpoints")
	}

	config := a.runnerArgs.config
	if a.runnerArgs.period != 0 {
		config.Period = a.runnerArgs.period
	}

	if r := NewCheckTCPPort(endpoints, config); r != nil {
		a.runnerArgs.runner = r
	}
	return nil
}

func createCheckTCPPortCmd(ra *runnerArgs) *cobra.Command {
	a := &checkTCPPortArgs{runnerArgs: ra}
	cmd := &cobra.Command{
		Use:   "checkTCPPort",
		Short: "checks connection to TCP port",
		RunE:  a.createRunner,
	}
	cmd.Flags().StringSliceVar(&a.endpoints, "endpoints", nil, "endpoints in format <hostname>:<ip>.:<port>.")
	cmd.Flags().IntVar(&a.nodePort, "node-port", 0, "port on nodes as alternative to specifying endpoints.")
	cmd.Flags().BoolVar(&a.podDS, "endpoints-of-pod-ds", false, "uses known pod endpoints of the 'nwpd-agent-pod-net' service.")
	cmd.Flags().BoolVar(&a.internalKAPI, "endpoint-internal-kube-apiserver", false, "uses known internal endpoint of kube-apiserver.")
	cmd.Flags().BoolVar(&a.externalKAPI, "endpoint-external-kube-apiserver", false, "uses known external endpoint of kube-apiserver.")
	return cmd
}

func NewCheckTCPPort(endpoints []config.Endpoint, rconfig RunnerConfig) *checkTCPPort {
	if len(endpoints) == 0 {
		return nil
	}
	return &checkTCPPort{
		endpoints: config.CloneAndShuffle(endpoints),
		config:    rconfig,
	}
}

type checkTCPPort struct {
	endpoints []config.Endpoint
	next      int
	config    RunnerConfig
}

var _ Runner = &checkTCPPort{}

func (r *checkTCPPort) Config() RunnerConfig {
	return r.config
}

func (r *checkTCPPort) Run(ch chan<- *nwpd.Observation) {
	endpoint := r.endpoints[r.next]
	r.next = (r.next + 1) % len(r.endpoints)

	nodeName := GetNodeName()
	obs := &nwpd.Observation{
		SrcHost:   nodeName,
		DestHost:  endpoint.Hostname,
		Timestamp: timestamppb.Now(),
		JobID:     r.config.JobID,
	}

	result, d, err := r.checkTCPPort(endpoint)
	obs.Duration = durationpb.New(d)
	obs.Ok = err == nil
	if err != nil {
		obs.Result = fmt.Sprintf("error: %s", err)
	} else {
		obs.Result = result
	}
	ch <- obs
}

func (r *checkTCPPort) checkTCPPort(endpoint config.Endpoint) (string, time.Duration, error) {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return "", 0, err
	}
	conn.Close()
	delta := time.Now().Sub(start)
	return "connected", delta, nil
}
