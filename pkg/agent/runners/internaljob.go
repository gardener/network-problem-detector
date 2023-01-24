/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package runners

import (
	"time"

	"go.uber.org/atomic"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"
)

type RunnerConfig struct {
	config.Job
	Period time.Duration
}

type Runner interface {
	Run(nodeName string, ch chan<- *nwpd.Observation)
	Config() RunnerConfig
	Description() string
	TestData() any
	DestHosts() []string
}

type InternalJob struct {
	runner        Runner
	peerNodeCount int
	active        atomic.Bool
	lastRun       atomic.Value
}

func NewInternalJob(runner Runner, peerNodeCount int) *InternalJob {
	return &InternalJob{
		runner:        runner,
		peerNodeCount: peerNodeCount,
	}
}

func (j *InternalJob) JobID() string {
	return j.runner.Config().JobID
}

func (j *InternalJob) Period() time.Duration {
	return j.runner.Config().Period
}

func (j *InternalJob) Config() RunnerConfig {
	return j.runner.Config()
}

func (j *InternalJob) Description() string {
	return j.runner.Description()
}

func (j *InternalJob) PeerNodeCount() int {
	return j.peerNodeCount
}

func (j *InternalJob) DestHosts() []string {
	return j.runner.DestHosts()
}

func (j *InternalJob) SetLastRun(lastRun *time.Time) {
	j.lastRun.Store(lastRun)
}

func (j *InternalJob) Tick(nodeName string, ch chan<- *nwpd.Observation) error {
	if j.runner == nil || j.active.Load() {
		return nil
	}

	now := time.Now()
	if now.After(j.getNextRun()) && j.active.CompareAndSwap(false, true) {
		j.lastRun.Store(&now)
		go func() {
			defer j.active.Store(false)
			j.runner.Run(nodeName, ch)
		}()
	}
	return nil
}

func (j *InternalJob) GetLastRun() *time.Time {
	v := j.lastRun.Load()
	if v == nil {
		return nil
	}
	return v.(*time.Time)
}

func (j *InternalJob) getNextRun() time.Time {
	last := j.GetLastRun()
	if last == nil {
		return time.Time{}
	}
	return last.Add(j.Period())
}
