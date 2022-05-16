/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	"sigs.k8s.io/yaml"
)

var DisableShuffleForTesting = false

func init() {
	rand.Seed(time.Now().UnixNano())
}

func LoadAgentConfig(configFile string, old *AgentConfig) (*AgentConfig, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	hashCode := hex.EncodeToString(sha256.New().Sum(data))
	if old != nil && old.hashCode == hashCode {
		return old, nil
	}

	cfg := &AgentConfig{}
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling %s failed: %w", configFile, err)
	}
	cfg.hashCode = hashCode
	return cfg, nil
}

func LoadClusterConfig(configFile string) (*ClusterConfig, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	cfg := &ClusterConfig{}
	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling %s failed: %w", configFile, err)
	}
	return cfg, nil
}

func CloneAndShuffle[T any](items []T) []T {
	if DisableShuffleForTesting {
		return items
	}
	if len(items) == 0 {
		return nil
	}
	clone := make([]T, len(items))
	copy(clone, items)
	rand.Shuffle(len(clone), func(i, j int) { clone[i], clone[j] = clone[j], clone[i] })
	return clone
}
