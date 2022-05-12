// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package agent

import (
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

func IncAggregatedObservation(src, dest, jobid string, ok bool) {
	status := "ok"
	if !ok {
		status = "failed"
	}
	AggregatedObservations.WithLabelValues(src, dest, jobid, status).Inc()
}

func ReportAggregatedObservationLatency(src, dest, jobid string, seconds float64) {
	AggregatedObservationsLatency.WithLabelValues(src, dest, jobid).Set(seconds)
}
