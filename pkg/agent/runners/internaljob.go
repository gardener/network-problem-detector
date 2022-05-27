/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package runners

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"
)

type RunnerConfig struct {
	config.Job
	Period time.Duration
}

type Runner interface {
	Run(ch chan<- *nwpd.Observation)
	Config() RunnerConfig
	Description() string
}

type InternalJob struct {
	runner   Runner
	ticker   *time.Ticker
	done     chan struct{}
	wg       sync.WaitGroup
	lastTick time.Time
}

func NewInternalJob(runner Runner) *InternalJob {
	return &InternalJob{
		runner: runner,
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

func (j *InternalJob) Start(ch chan<- *nwpd.Observation, initialWait time.Duration) error {
	if j.ticker != nil {
		return fmt.Errorf("already started")
	}
	if j.runner == nil {
		return nil
	}
	j.ticker = time.NewTicker(j.runner.Config().Period)
	j.done = make(chan struct{})
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	j.wg.Add(1)
	go func() {
		time.Sleep(initialWait)
	loop:
		for {
			j.lastTick = time.Now()
			j.runner.Run(ch)
			select {
			case <-j.done:
				break loop
			case <-interrupt:
				break loop
			case <-j.ticker.C:
				continue
			}
		}
		j.ticker.Stop()
		j.wg.Done()
	}()
	return nil
}

func (j *InternalJob) Stop() (time.Duration, error) {
	if j.ticker == nil || j.runner == nil {
		return 0, nil
	}
	j.ticker.Stop()
	j.done <- struct{}{}
	j.wg.Wait()
	j.ticker = nil
	return time.Now().Sub(j.lastTick), nil
}
