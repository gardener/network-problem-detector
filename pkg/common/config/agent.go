// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AgentConfig struct {
	// OutputDir is the directory to store the observations.
	OutputDir string `json:"outputDir,omitempty"`
	// RetentionHours defines how many hours to keep old observations.
	RetentionHours int `json:"retentionHours,omitempty"`
	// LogObservations defines if observations should be logged additionally (for debug purposes)
	LogObservations bool `json:"logObservations"`
	// K8sExporter defines configuration of the K8s exporter for writing node conditions and events
	K8sExporter *K8sExporterConfig `json:"k8sExporter,omitempty"`
	// AggregationReportPeriod defines how often aggregated report is logged.
	AggregationReportPeriod *metav1.Duration `json:"aggregationReportPeriod,omitempty"`
	// AggregationTimeWindow defines when a aggregation edge outdates if no new observations arrive
	AggregationTimeWindow *metav1.Duration `json:"aggregationTimeWindow,omitempty"`
	// HostNetwork is the configuration specific for daemon set in node network
	HostNetwork *NetworkConfig `json:"hostNetwork,omitempty"`
	// PodNetwork is the configuration specific for daemon set in node network
	PodNetwork *NetworkConfig `json:"podNetwork,omitempty"`
}

func (c *AgentConfig) Clone() (*AgentConfig, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	clone := &AgentConfig{}
	if err = json.Unmarshal(data, clone); err != nil {
		return nil, err
	}
	return clone, nil
}

type NetworkConfig struct {
	// DataFilePrefix is the prefix for observation data files.
	DataFilePrefix string `json:"dataFilePrefix,omitempty"`
	// HttpPort is the port of the http server.
	HttpPort int `json:"httpPort,omitempty"`
	// Jobs are the jobs to execute.
	Jobs []Job `json:"jobs,omitempty"`
	// DefaultPeriod is the period used for a new job if it doesn't specify the period.
	DefaultPeriod metav1.Duration `json:"defaultPeriod,omitempty"`
}

type Job struct {
	JobID string   `json:"jobID"`
	Args  []string `json:"args,omitempty"`
}

type K8sExporterConfig struct {
	// Enabled if true, the K8s exporter is active and patches the node conditions periodically.
	Enabled bool `json:"enabled"`
	// HeartbeatPeriod defines the update frequency of the node conditions.
	HeartbeatPeriod *metav1.Duration `json:"heartbeatPeriod,omitempty"`
}
