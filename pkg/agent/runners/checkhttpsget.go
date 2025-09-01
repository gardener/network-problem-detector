// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/config"

	"github.com/spf13/cobra"
)

const (
	caFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 - only path to credentials
)

type checkHTTPSGetArgs struct {
	runnerArgs   *runnerArgs
	internalKAPI bool
	externalKAPI bool
	endpoints    []string
}

type CheckHTTPSEndpoint struct {
	config.Endpoint
	AuthBySAToken bool
}

func (a *checkHTTPSGetArgs) createRunner(_ *cobra.Command, _ []string) error {
	allowEmpty := false
	var endpoints []CheckHTTPSEndpoint
	switch {
	case len(a.endpoints) > 0:
		for _, ep := range a.endpoints {
			parts := strings.SplitN(ep, ":", 2)
			port := 443
			if len(parts) == 2 {
				var err error
				port, err = strconv.Atoi(parts[1])
				if err != nil {
					return fmt.Errorf("invalid endpoint port %s", parts[1])
				}
			}
			endpoints = append(endpoints, CheckHTTPSEndpoint{
				Endpoint: config.Endpoint{
					Hostname: parts[0],
					IP:       "",
					Port:     port,
				},
			})
		}
	case a.internalKAPI:
		endpoints = append(endpoints, CheckHTTPSEndpoint{
			Endpoint: config.Endpoint{
				Hostname: common.DomainNameKubernetesService,
				IP:       "",
				Port:     443,
			},
			AuthBySAToken: true,
		})
	case a.externalKAPI:
		allowEmpty = true
		if host := os.Getenv(common.EnvAPIServerHost); len(host) > 0 {
			port := 443
			if envPort := os.Getenv(common.EnvAPIServerPort); len(envPort) > 0 {
				p, err := strconv.Atoi(envPort)
				if err != nil {
					return fmt.Errorf("invalid API server port %s: %w", envPort, err)
				}
				port = p
			}
			if strings.TrimSpace(host) == "" {
				return fmt.Errorf("invalid API server host %q: hostname cannot be empty", host)
			}
			if port == 0 || port > 65535 {
				return fmt.Errorf("invalid API server port %q: port must be between 1 and 65535", port)
			}
			endpoints = append(endpoints, CheckHTTPSEndpoint{
				Endpoint: config.Endpoint{
					Hostname: host,
					IP:       "",
					Port:     port,
				},
				AuthBySAToken: true,
			})
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

func NewCheckHTTPSGet(endpoints []CheckHTTPSEndpoint, rconfig RunnerConfig) Runner {
	if len(endpoints) == 0 {
		return nil
	}
	return &checkHTTPSGet{
		robinRound[CheckHTTPSEndpoint]{
			itemsName: "endpoints",
			items:     config.CloneAndShuffle(endpoints),
			runFunc:   checkHTTPSGetFunc,
			config:    rconfig,
		},
	}
}

type checkHTTPSGet struct {
	robinRound[CheckHTTPSEndpoint]
}

var _ Runner = &checkHTTPSGet{}

func checkHTTPSGetFunc(endpoint CheckHTTPSEndpoint) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- connection check only, no sensitive data
	}
	if endpoint.AuthBySAToken {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return "", fmt.Errorf("reading CA file %s failed: %w", caFile, err)
		}
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM(caPEM); !ok {
			return "", fmt.Errorf("failed to parse root certificate from %s", caFile)
		}
		tr.TLSClientConfig.InsecureSkipVerify = false
		tr.TLSClientConfig.RootCAs = roots
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s:%d", endpoint.Hostname, endpoint.Port)
	if endpoint.AuthBySAToken {
		url = fmt.Sprintf("https://%s:%d/api", endpoint.Hostname, endpoint.Port)
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	if endpoint.AuthBySAToken {
		token, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading token from file %s failed: %w", tokenFile, err)
		}
		request.Header.Set("Authorization", "Bearer "+string(token))
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Status, nil
}
