// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	prometheus.MustRegister(AggregatedObservations)
	prometheus.MustRegister(AggregatedObservationsLatency)
}

var (
	AggregatedObservations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nwpd_aggregated_observations",
			Help: "Total counts of observations",
		},
		[]string{"src", "dest", "jobid", "status"},
	)
	AggregatedObservationsLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nwpd_aggregated_observations_latency_secs",
			Help: "Observation duration in seconds",
		},
		[]string{"src", "dest", "jobid"},
	)
)

type observationKey struct {
	src   string
	dest  string
	jobid string
}

type observationKeys struct {
	lock sync.Mutex
	keys map[observationKey]struct{}
}

var metricKeys = observationKeys{
	keys: map[observationKey]struct{}{},
}

func (k *observationKeys) add(src, dest, jobid string) {
	k.lock.Lock()
	defer k.lock.Unlock()
	key := observationKey{
		src:   src,
		dest:  dest,
		jobid: jobid,
	}
	if _, ok := k.keys[key]; !ok {
		k.keys[key] = struct{}{}
	}
}

func (k *observationKeys) remove(isObsolete func(key observationKey) bool) []observationKey {
	k.lock.Lock()
	defer k.lock.Unlock()

	var keys []observationKey
	for key := range k.keys {
		if isObsolete(key) {
			keys = append(keys, key)
			delete(k.keys, key)
		}
	}
	return keys
}

func IncAggregatedObservation(src, dest, jobid string, ok bool) {
	status := "ok"
	if !ok {
		status = "failed"
	}
	metricKeys.add(src, dest, jobid)
	AggregatedObservations.WithLabelValues(src, dest, jobid, status).Inc()
}

func ReportAggregatedObservationLatency(src, dest, jobid string, seconds float64) {
	AggregatedObservationsLatency.WithLabelValues(src, dest, jobid).Set(seconds)
}

func deleteOutdatedMetricByObsoleteJobIDs(jobIDs []string) {
	if len(jobIDs) > 0 {
		keys := metricKeys.remove(func(key observationKey) bool {
			for _, id := range jobIDs {
				if key.jobid == id {
					return true
				}
			}
			return false
		})
		deleteOutdatedMetricsByKeys(keys)
	}
}

func deleteOutdatedMetricByValidDestHosts(validDestHosts map[string]struct{}) {
	keys := metricKeys.remove(func(key observationKey) bool {
		_, oksrc := validDestHosts[key.src]
		_, okdest := validDestHosts[key.dest]
		return !oksrc || !okdest
	})
	deleteOutdatedMetricsByKeys(keys)
}

func deleteOutdatedMetricsByKeys(keys []observationKey) {
	for _, key := range keys {
		AggregatedObservations.DeleteLabelValues(key.src, key.dest, key.jobid, "ok")
		AggregatedObservations.DeleteLabelValues(key.src, key.dest, key.jobid, "failed")
		AggregatedObservationsLatency.DeleteLabelValues(key.src, key.dest, key.jobid)
	}
}
