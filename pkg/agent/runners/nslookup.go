// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"bytes"
	"fmt"
	"net"

	"github.com/gardener/network-problem-detector/pkg/common/config"

	"github.com/spf13/cobra"
)

type nslookupArgs struct {
	runnerArgs   *runnerArgs
	internalKAPI bool
	externalKAPI bool
	names        []string
}

func (a *nslookupArgs) createRunner(_ *cobra.Command, _ []string) error {
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

func NewNSLookup(names []string, rconfig RunnerConfig) Runner {
	if len(names) == 0 {
		return nil
	}
	var dnsNames []dnsName
	for _, name := range names {
		dnsNames = append(dnsNames, dnsName(name))
	}
	return &nslookup{
		robinRound[dnsName]{
			itemsName: "names",
			items:     config.CloneAndShuffle(dnsNames),
			runFunc:   lookupFunc,
			config:    rconfig,
		},
	}
}

type dnsName string

func (n dnsName) DestHost() string {
	return normalise(string(n))
}

type nslookup struct {
	robinRound[dnsName]
}

var _ Runner = &nslookup{}

func lookupFunc(name dnsName) (string, error) {
	ips, err := net.LookupIP(string(name))
	if err != nil {
		return "", err
	}
	sb := bytes.Buffer{}
	for _, ip := range ips {
		if sb.Len() > 0 {
			sb.Write([]byte(","))
		}
		sb.Write([]byte(ip.String()))
	}
	return sb.String(), nil
}
