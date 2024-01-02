// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"

	"github.com/spf13/cobra"
)

type checkHTTPSGetArgs struct {
	runnerArgs   *runnerArgs
	internalKAPI bool
	externalKAPI bool
	endpoints    []string
}

func (a *checkHTTPSGetArgs) createRunner(_ *cobra.Command, _ []string) error {
	allowEmpty := false
	var endpoints []config.Endpoint
	switch {
	case len(a.endpoints) > 0:
		for _, ep := range a.endpoints {
			parts := strings.SplitN(ep, ":", 2)
			if len(parts) != 1 && len(parts) != 2 {
				return fmt.Errorf("invalid endpoint %s", ep)
			}
			port := 443
			if len(parts) == 2 {
				var err error
				port, err = strconv.Atoi(parts[1])
				if err != nil {
					return fmt.Errorf("invalid endpoint port %s", parts[1])
				}
			}
			endpoints = append(endpoints, config.Endpoint{
				Hostname: parts[0],
				IP:       "",
				Port:     port,
			})
		}
	case a.internalKAPI:
		endpoints = append(endpoints, config.Endpoint{
			Hostname: common.DomainNameKubernetesService,
			IP:       "",
			Port:     443,
		})
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
	if r := NewCheckHTTPSGet(endpoints, config); r != nil {
		a.runnerArgs.runner = r
	}
	return nil
}

func createCheckHTTPSGetArgs(ra *runnerArgs) *cobra.Command {
	a := &checkHTTPSGetArgs{runnerArgs: ra}
	cmd := &cobra.Command{
		Use:   "checkHTTPSGet",
		Short: "performs an HTTPS Get request to given hostname (and port)",
		RunE:  a.createRunner,
	}
	cmd.Flags().StringSliceVar(&a.endpoints, "endpoints", nil, "endpoints in format <hostname>[:<port>].")
	cmd.Flags().BoolVar(&a.internalKAPI, "endpoint-internal-kube-apiserver", false, "uses known internal endpoint of kube-apiserver.")
	cmd.Flags().BoolVar(&a.externalKAPI, "endpoint-external-kube-apiserver", false, "uses known external endpoint of kube-apiserver.")
	return cmd
}

func NewCheckHTTPSGet(endpoints []config.Endpoint, rconfig RunnerConfig) Runner {
	if len(endpoints) == 0 {
		return nil
	}
	return &checkHTTPSGet{
		robinRound[config.Endpoint]{
			itemsName: "endpoints",
			items:     config.CloneAndShuffle(endpoints),
			runFunc:   checkHTTPSGetFunc,
			config:    rconfig,
		},
	}
}

type checkHTTPSGet struct {
	robinRound[config.Endpoint]
}

var _ Runner = &checkHTTPSGet{}

func checkHTTPSGetFunc(endpoint config.Endpoint) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s:%d", endpoint.Hostname, endpoint.Port)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Status, nil
}
