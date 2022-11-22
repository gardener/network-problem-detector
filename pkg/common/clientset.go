/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package common

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type ClientsetBase struct {
	Kubeconfig string
	InCluster  bool
	Clientset  *kubernetes.Clientset
}

func (b *ClientsetBase) AddKubeConfigFlag(flags *pflag.FlagSet) {
	flags.StringVar(&b.Kubeconfig, "kubeconfig", "", "kubeconfig for shoot cluster, uses KUBECONFIG if not specified.")
}

func (b *ClientsetBase) AddInClusterFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&b.InCluster, "in-cluster", false, "if controller runs inside a pod")
}

func (b *ClientsetBase) SetupClientSet() error {
	config, err := b.RestConfig()
	if err != nil {
		return err
	}
	b.Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating clientset: %s", err)
	}
	return nil
}

func (b *ClientsetBase) RestConfig() (*rest.Config, error) {
	var err error
	var config *rest.Config
	if b.InCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("error on InClusterConfig: %s", err)
		}
	} else {
		if b.Kubeconfig == "" {
			b.Kubeconfig = os.Getenv("KUBECONFIG")
		}
		if b.Kubeconfig == "" {
			if home := homedir.HomeDir(); home != "" {
				b.Kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
		if b.Kubeconfig == "" {
			return nil, fmt.Errorf("cannot find kubeconfig: neither '--kubeconfig' option, env var 'KUBECONFIG', or file '$HOME/.kube/config' available")
		}
		config, err = clientcmd.BuildConfigFromFlags("", b.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("error on config from kubeconfig file %s: %s", b.Kubeconfig, err)
		}
	}
	return config, nil
}
