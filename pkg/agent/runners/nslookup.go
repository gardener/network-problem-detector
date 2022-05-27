// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type nslookupArgs struct {
	runnerArgs   *runnerArgs
	internalKAPI bool
	externalKAPI bool
	names        []string
}

func (a *nslookupArgs) createRunner(cmd *cobra.Command, args []string) error {
	allowEmpty := false
	var names []string
	if len(a.names) > 0 {
		for _, name := range a.names {
			names = append(names, fullQualified(name))
		}
	}
	if a.internalKAPI {
		names = append(names, "kubernetes.default.svc.cluster.local.")
	}
	if a.externalKAPI {
		allowEmpty = true
		if pe := a.runnerArgs.clusterCfg.KubeAPIServer; pe != nil {
			names = append(names, fullQualified(pe.Hostname))
		}
	}

	if !allowEmpty && len(names) == 0 {
		return fmt.Errorf("no DNS names")
	}

	config := a.runnerArgs.prepareConfig()
	if r := NewNSLookup(names, config); r != nil {
		a.runnerArgs.runner = r
	}
	return nil
}

func createNSLookupCmd(ra *runnerArgs) *cobra.Command {
	a := &nslookupArgs{runnerArgs: ra}
	cmd := &cobra.Command{
		Use:   "nslookup",
		Short: "DNS host lookup",
		RunE:  a.createRunner,
	}
	cmd.Flags().StringSliceVar(&a.names, "names", nil, "DNS names")
	cmd.Flags().BoolVar(&a.internalKAPI, "name-internal-kube-apiserver", false, "uses DNS name 'kubernetes.default.svc.cluster.local.'")
	cmd.Flags().BoolVar(&a.externalKAPI, "name-external-kube-apiserver", false, "uses known external DNS name of kube-apiserver.")
	return cmd
}

func NewNSLookup(names []string, rconfig RunnerConfig) *nslookup {
	if len(names) == 0 {
		return nil
	}
	return &nslookup{
		names:  config.CloneAndShuffle(names),
		config: rconfig,
	}
}

type nslookup struct {
	names  []string
	next   int
	config RunnerConfig
}

var _ Runner = &nslookup{}

func (r *nslookup) Config() RunnerConfig {
	return r.config
}

func (r *nslookup) Description() string {
	return fmt.Sprintf("%d names", len(r.names))
}

func (r *nslookup) Run(ch chan<- *nwpd.Observation) {
	name := r.names[r.next]
	r.next = (r.next + 1) % len(r.names)

	nodeName := GetNodeName()
	obs := &nwpd.Observation{
		SrcHost:   nodeName,
		DestHost:  normalise(name),
		Timestamp: timestamppb.Now(),
		JobID:     r.config.JobID,
	}

	result, d, err := r.lookup(name)
	obs.Duration = durationpb.New(d)
	obs.Ok = err == nil
	if err != nil {
		obs.Result = fmt.Sprintf("error: %s", err)
	} else {
		obs.Result = result
	}
	ch <- obs
}

func (r *nslookup) lookup(name string) (string, time.Duration, error) {
	start := time.Now()
	ips, err := net.LookupIP(name)
	delta := time.Now().Sub(start)
	if err != nil {
		return "", delta, err
	}
	sb := bytes.Buffer{}
	for _, ip := range ips {
		if sb.Len() > 0 {
			sb.Write([]byte(","))
		}
		sb.Write([]byte(ip.String()))
	}
	return sb.String(), delta, nil
}
