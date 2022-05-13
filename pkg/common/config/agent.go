// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"time"
)

type AgentConfig struct {
	ClusterConfig

	// OutputDir is the directory to store the observations.
	OutputDir string `json:"outputDir,omitempty"`
	// RetentionHours defines how many hours to keep old observations.
	RetentionHours int `json:"retentionHours,omitempty"`
	// LogDroppingFactor defines the dropping factor of observations log entries
	LogDroppingFactor float32 `json:"logDroppingFactor,omitempty"`
	// AggregationReportPeriodSeconds defines how often aggregated report is logged. Default is 60s if not set
	AggregationReportPeriodSeconds *int `json:"aggregationReportPeriodSeconds,omitempty"`
	// AggregationTimeWindowSeconds defines when a aggregation edge outdates if no new observations arrive
	AggregationTimeWindowSeconds *int `json:"aggregationTimeWindowSeconds,omitempty"`
	// NodeNetwork is the configuration specific for daemon set in node network
	NodeNetwork *NetworkConfig `json:"nodeNetwork,omitempty"`
	// PodNetwork is the configuration specific for daemon set in node network
	PodNetwork *NetworkConfig `json:"podNetwork,omitempty"`

	hashCode string
}

type NetworkConfig struct {
	// DataFilePrefix is the prefix for observation data files.
	DataFilePrefix string `json:"dataFilePrefix,omitempty"`
	// GRPCPort is the port of the GRPC server. If 0, a dynamic port is used.
	GRPCPort int `json:"grpcPort,omitempty"`
	// HttpPort is the port of the http server.
	HttpPort int `json:"httpPort,omitempty"`
	// Jobs are the jobs to execute.
	Jobs []Job `json:"jobs,omitempty"`
	// StartMDNSServer specifies if the MDNS server should be started.
	StartMDNSServer bool `json:"startMDNSServer,omitempty"`
	// DefaultPeriod is the period used for a new job if it doesn't specify the period.
	DefaultPeriod time.Duration `json:"defaultPeriod,omitempty"`
}

type Job struct {
	JobID string   `json:"jobID"`
	Args  []string `json:"args,omitempty"`
}
