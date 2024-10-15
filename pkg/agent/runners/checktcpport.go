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

	"github.com/spf13/cobra"
	k8snetutils "k8s.io/utils/net"
)

type checkTCPPortArgs struct {
	runnerArgs   *runnerArgs
	nodePort     int
	podDS        bool
	internalKAPI bool
	externalKAPI bool
	endpoints    []string
}

func (a *checkTCPPortArgs) createRunner(_ *cobra.Command, _ []string) error {
	allowEmpty := false
	var endpoints []config.Endpoint
	switch {
	case len(a.endpoints) > 0:
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
	case a.nodePort != 0:
		allowEmpty = true
		for _, n := range a.runnerArgs.clusterCfg.Nodes {
			endpoints = append(endpoints, config.Endpoint{
				Hostname: n.Hostname,
				IP:       n.InternalIP,
				Port:     a.nodePort,
			})
		}
	case a.podDS:
		allowEmpty = true
		for _, pe := range a.runnerArgs.clusterCfg.PodEndpoints {
			endpoints = append(endpoints, config.Endpoint{
				Hostname: pe.Nodename,
				IP:       pe.PodIP,
				Port:     int(pe.Port),
			})
		}
	case a.internalKAPI:
		allowEmpty = true
		if pe := a.runnerArgs.clusterCfg.InternalKubeAPIServer; pe != nil {
			endpoints = append(endpoints, *pe)
		}
	case a.externalKAPI:
		allowEmpty = true
		if pe := a.runnerArgs.clusterCfg.KubeAPIServer; pe != nil {
			endpoints = append(endpoints, *pe)
		}
	}

	if !allowEmpty && len(endpoints) == 0 {
		return fmt.Errorf("no endpoints")
	}

	config := a.runnerArgs.prepareConfig()
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
	cmd.Flags().StringSliceVar(&a.endpoints, "endpoints", nil, "endpoints in format <hostname>:<ip>:<port>.")
	cmd.Flags().IntVar(&a.nodePort, "node-port", 0, "port on nodes as alternative to specifying endpoints.")
	cmd.Flags().BoolVar(&a.podDS, "endpoints-of-pod-ds", false, "uses known pod endpoints of the 'nwpd-agent-pod-net' service.")
	cmd.Flags().BoolVar(&a.internalKAPI, "endpoint-internal-kube-apiserver", false, "uses known internal endpoint of kube-apiserver.")
	cmd.Flags().BoolVar(&a.externalKAPI, "endpoint-external-kube-apiserver", false, "uses known external endpoint of kube-apiserver.")
	return cmd
}

func NewCheckTCPPort(endpoints []config.Endpoint, rconfig RunnerConfig) Runner {
	if len(endpoints) == 0 {
		return nil
	}
	return &checkTCPPort{
		robinRound[config.Endpoint]{
			itemsName: "endpoints",
			items:     config.CloneAndShuffle(endpoints),
			runFunc:   checkTCPPortFunc,
			config:    rconfig,
		},
	}
}

type checkTCPPort struct {
	robinRound[config.Endpoint]
}

var _ Runner = &checkTCPPort{}

func checkTCPPortFunc(endpoint config.Endpoint) (string, error) {
	addr := fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port)
	if k8snetutils.IsIPv6(net.ParseIP(endpoint.IP)) {
		addr = fmt.Sprintf("[%s]:%d", endpoint.IP, endpoint.Port)
	}
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return "", err
	}
	_ = conn.Close()
	return "connected", nil
}
