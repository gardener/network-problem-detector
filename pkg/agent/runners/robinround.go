// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package runners

import (
	"fmt"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type runFunc[T config.WithDestHost] func(item T) (result string, err error)

type robinRound[T config.WithDestHost] struct {
	itemsName string
	runFunc   runFunc[T]
	items     []T
	next      int
	config    RunnerConfig
}

func (r *robinRound[T]) Config() RunnerConfig {
	return r.config
}

func (r *robinRound[T]) Description() string {
	return fmt.Sprintf("%d %s", len(r.items), r.itemsName)
}

func (r *robinRound[T]) TestData() any {
	return r.items
}

func (r *robinRound[T]) DestHosts() []string {
	hosts := make([]string, len(r.items))
	for i := range r.items {
		hosts[i] = r.items[i].DestHost()
	}
	return hosts
}

func (r *robinRound[T]) Run(ch chan<- *nwpd.Observation) {
	item := r.items[r.next]
	r.next = (r.next + 1) % len(r.items)

	nodeName := GetNodeName()
	obs := &nwpd.Observation{
		SrcHost:   nodeName,
		DestHost:  item.DestHost(),
		Timestamp: timestamppb.Now(),
		JobID:     r.config.JobID,
	}

	start := time.Now()
	result, err := r.runFunc(item)
	obs.Duration = durationpb.New(time.Since(start))
	obs.Period = durationpb.New(r.config.Period * time.Duration(len(r.items)))
	obs.Ok = err == nil
	if err != nil {
		obs.Result = fmt.Sprintf("error: %s", err)
	} else {
		obs.Result = result
	}
	ch <- obs
}
