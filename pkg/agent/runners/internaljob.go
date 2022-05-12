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
	"strings"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/config"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"
)

type RunnerConfig struct {
	JobID  string
	Period time.Duration
}

type Runner interface {
	Run(ch chan<- *nwpd.Observation)
	Config() RunnerConfig
}

type InternalJob struct {
	JobID string
	Args  []string

	runner Runner
	ticker *time.Ticker
	done   chan struct{}
	wg     sync.WaitGroup
}

func NewInternalJob(job *config.Job, runner Runner) *InternalJob {
	return &InternalJob{
		JobID:  job.JobID,
		Args:   job.Args[:],
		runner: runner,
	}
}

func (j *InternalJob) Matches(filter string) bool {
	if filter == "" {
		return true
	}
	if strings.Contains(j.JobID, filter) {
		return true
	}
	for _, arg := range j.Args {
		if strings.Contains(arg, filter) {
			return true
		}
	}
	return false
}

func (j *InternalJob) Start(ch chan<- *nwpd.Observation) error {
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
	loop:
		for {
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

func (j *InternalJob) Stop() error {
	if j.ticker == nil || j.runner == nil {
		return nil
	}
	j.ticker.Stop()
	j.done <- struct{}{}
	j.wg.Wait()
	j.ticker = nil
	return nil
}
