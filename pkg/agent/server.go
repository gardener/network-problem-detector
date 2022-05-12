// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/aggregation"
	"github.com/gardener/network-problem-detector/pkg/agent/db"
	"github.com/gardener/network-problem-detector/pkg/agent/runners"
	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type server struct {
	lock        sync.Mutex
	log         logrus.FieldLogger
	configFile  string
	hostNetwork bool
	jobs        []*nwpd.InternalJob
	clusterCfg  nwpd.ClusterConfig
	revision    atomic.Int64
	lastConfig  *Config
	obsChan     chan *nwpd.Observation
	writer      nwpd.ObservationWriter
	aggregator  nwpd.ObservationListener
	done        chan struct{}
	ticker      *time.Ticker

	nwpd.UnimplementedAgentServiceServer
}

func newServer(log logrus.FieldLogger, configFile string, hostNetwork bool) (*server, error) {
	return &server{
		log:         log,
		configFile:  configFile,
		hostNetwork: hostNetwork,
		obsChan:     make(chan *nwpd.Observation, 100),
		done:        make(chan struct{}),
		ticker:      time.NewTicker(30 * time.Second),
	}, nil
}

func (s *server) isHostNetwork() bool {
	return s.hostNetwork
}

func (s *server) getNetworkCfg() *NetworkConfig {
	networkCfg := &NetworkConfig{}
	if s.lastConfig != nil {
		if hostNetwork && s.lastConfig.NodeNetwork != nil {
			networkCfg = s.lastConfig.NodeNetwork
		} else if !hostNetwork && s.lastConfig.PodNetwork != nil {
			networkCfg = s.lastConfig.PodNetwork
		}
	}
	return networkCfg
}

func (s *server) setup() error {
	cfg, err := loadConfig(configFile, s.lastConfig)
	if err != nil {
		return err
	}

	reportPeriod := 60 * time.Second
	timeWindow := 10 * time.Minute
	if cfg.AggregationReportPeriodSeconds != nil {
		reportPeriod = time.Duration(*cfg.AggregationReportPeriodSeconds) * time.Second
	}
	if cfg.AggregationTimeWindowSeconds != nil {
		timeWindow = time.Duration(*cfg.AggregationTimeWindowSeconds) * time.Second
	}
	s.aggregator = aggregation.NewObsAggregator(s.log.WithField("sub", "aggr"), reportPeriod, timeWindow)

	return s.applyConfig(cfg)
}

func (s *server) applyConfig(cfg *Config) error {
	networkCfg := &NetworkConfig{}
	if hostNetwork && cfg.NodeNetwork != nil {
		networkCfg = cfg.NodeNetwork
	} else if !hostNetwork && cfg.PodNetwork != nil {
		networkCfg = cfg.PodNetwork
	}

	if cfg.OutputDir != "" && s.writer == nil {
		prefix := "agent"
		if networkCfg.DataFilePrefix != "" {
			prefix = networkCfg.DataFilePrefix
		}
		var err error
		s.writer, err = db.NewObsWriter(s.log.WithField("sub", "writer"), cfg.OutputDir, prefix, cfg.RetentionHours)
		if err != nil {
			return err
		}
	}
	s.clusterCfg = cfg.ClusterConfig

	for _, j := range networkCfg.Jobs {
		job, err := s.parseJob(&j)
		if err != nil {
			return err
		}
		err = s.addOrReplaceJob(job)
		if err != nil {
			return err
		}
	}

	s.lastConfig = cfg
	return nil
}

func (s *server) parseJob(job *nwpd.Job) (*nwpd.InternalJob, error) {
	n := len(job.Args)
	if n == 0 {
		return nil, fmt.Errorf("no job args")
	}

	defaultPeriod := 1 * time.Second
	if s.getNetworkCfg().DefaultPeriod != 0 {
		defaultPeriod = s.getNetworkCfg().DefaultPeriod
	}
	config := nwpd.RunnerConfig{
		JobID:  job.JobID,
		Period: defaultPeriod,
	}
	runner, err := runners.Parse(s.clusterCfg, config, job.Args, true)
	if err != nil {
		return nil, fmt.Errorf("invalid job %s: %s", job.JobID, err)
	}
	return nwpd.NewInternalJob(job, runner), nil
}

func (s *server) addOrReplaceJob(job *nwpd.InternalJob) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i, j := range s.jobs {
		if j.JobID == job.JobID {
			err := s.jobs[i].Stop()
			if err != nil {
				return err
			}
			s.jobs[i] = job
			return job.Start(s.obsChan)
		}
	}
	s.jobs = append(s.jobs, job)
	return job.Start(s.obsChan)
}

func (s *server) GetObservations(_ context.Context, request *nwpd.GetObservationsRequest) (*nwpd.GetObservationsResponse, error) {
	options := nwpd.ListObservationsOptions{
		Limit:           int(request.Limit),
		FilterJobIDs:    request.RestrictToJobIDs,
		FilterSrcHosts:  request.RestrictToSrcHosts,
		FilterDestHosts: request.RestrictToDestHosts,
		FailuresOnly:    request.FailuresOnly,
	}
	if request.Start != nil {
		options.Start = request.Start.AsTime()
	}
	if request.End != nil {
		options.End = request.End.AsTime()
	}
	result, err := s.writer.ListObservations(options)
	if err != nil {
		return nil, err
	}
	return &nwpd.GetObservationsResponse{
		Observations: result,
	}, nil
}

type edge struct {
	src  string
	dest string
}

func (s *server) GetAggregatedObservations(ctx context.Context, request *nwpd.GetObservationsRequest) (*nwpd.GetAggregatedObservationsResponse, error) {
	resp, err := s.GetObservations(ctx, request)
	if err != nil {
		return nil, err
	}
	result := resp.Observations
	if len(result) == 0 {
		return &nwpd.GetAggregatedObservationsResponse{}, nil
	}
	rstart := result[0].Timestamp.AsTime()
	rdelta := 1 * time.Minute
	if request.AggregationWindow != nil && request.AggregationWindow.AsDuration().Milliseconds() > 30000 {
		rdelta = request.AggregationWindow.AsDuration()
	}
	if request.Start != nil {
		rstart = request.Start.AsTime()
	}
	currEnd := rstart.Add(rdelta)
	var aggregated []*nwpd.AggregatedObservation
	currAggr := map[edge]*nwpd.AggregatedObservation{}
	addAggregations := func() {
		for _, aggr := range currAggr {
			for k, c := range aggr.JobsOkCount {
				if dur := aggr.MeanOkDuration[k]; dur != nil {
					aggr.MeanOkDuration[k] = durationpb.New(dur.AsDuration() / time.Duration(c))
				}
			}
			aggregated = append(aggregated, aggr)
		}
		currAggr = map[edge]*nwpd.AggregatedObservation{}
	}
	for _, obs := range result {
		for !obs.Timestamp.AsTime().Before(currEnd) {
			rstart = currEnd
			currEnd = rstart.Add(rdelta)
			addAggregations()
		}

		edge := edge{src: obs.SrcHost, dest: obs.DestHost}
		aggr := currAggr[edge]
		if aggr == nil {
			aggr = &nwpd.AggregatedObservation{
				SrcHost:        obs.SrcHost,
				DestHost:       obs.DestHost,
				PeriodStart:    timestamppb.New(rstart),
				PeriodEnd:      timestamppb.New(currEnd),
				JobsOkCount:    map[string]int32{},
				JobsNotOkCount: map[string]int32{},
				MeanOkDuration: map[string]*durationpb.Duration{},
			}
			currAggr[edge] = aggr
		}
		if obs.Ok {
			aggr.JobsOkCount[obs.JobID]++
			if obs.Duration != nil {
				dur := 0 * time.Second
				if d := aggr.MeanOkDuration[obs.JobID]; d != nil {
					dur = d.AsDuration()
				}
				dur += obs.Duration.AsDuration()
				aggr.MeanOkDuration[obs.JobID] = durationpb.New(dur)
			}
		} else {
			aggr.JobsNotOkCount[obs.JobID]++
		}
	}
	addAggregations()

	return &nwpd.GetAggregatedObservationsResponse{
		AggregatedObservations: aggregated,
	}, nil
}

func (s *server) stop() {
	if s.ticker != nil {
		s.ticker.Stop()
		s.ticker = nil
	}
	if s.writer != nil {
		s.writer.Stop()
		s.writer = nil
	}
}

func (s *server) reloadConfig() {
	cfg, err := loadConfig(s.configFile, s.lastConfig)
	if err != nil {
		s.log.Warnf("cannot load configuration from %s", s.configFile)
		return
	}
	if cfg != s.lastConfig {
		err = s.applyConfig(cfg)
		if err != nil {
			s.log.Warnf("cannot apply new configuration from %s", s.configFile)
			return
		}
		s.log.Infof("reloaded configuration from %s", s.configFile)
	}
}

func (s *server) run() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	if metrics {
		port := common.PodNetPodMetricsPort
		if hostNetwork {
			port = common.NodeNetPodMetricsPort
		}
		s.log.Infof("provide metrics at ':%d/metrics'", port)
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
		}()
	}
	if s.writer != nil {
		go s.writer.Run()
	}

	for {
		select {
		case <-s.done:
			s.stop()
			return
		case <-interrupt:
			s.stop()
			return
		case obs := <-s.obsChan:
			logObservation := s.lastConfig.LogDroppingFactor == 0 || rand.Float32() > s.lastConfig.LogDroppingFactor
			if logObservation {
				fields := logrus.Fields{
					"src":   obs.SrcHost,
					"dest":  obs.DestHost,
					"ok":    obs.Ok,
					"jobid": obs.JobID,
					"time":  obs.Timestamp.AsTime(),
				}
				s.log.WithFields(fields).Info(obs.Result)
			}
			IncAggregatedObservation(obs.SrcHost, obs.DestHost, obs.JobID, obs.Ok)
			if obs.Ok && obs.Duration != nil {
				ReportAggregatedObservationLatency(obs.SrcHost, obs.DestHost, obs.JobID, obs.Duration.AsDuration().Seconds())
			}
			if s.writer != nil {
				s.writer.Add(obs)
			}
			if s.aggregator != nil {
				s.aggregator.Add(obs)
			}
		case <-s.ticker.C:
			go s.reloadConfig()
		}
	}
}
