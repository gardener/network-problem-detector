/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package aggregation

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/condition"
	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/problemclient"
	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/types"
	"github.com/gardener/network-problem-detector/pkg/agent/version"
	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/clock"
)

type k8sExporter struct {
	log              logrus.FieldLogger
	client           problemclient.Client
	conditionManager condition.ConditionManager
}

// newExporter creates a exporter for Kubernetes apiserver exporting,
func newExporter(log logrus.FieldLogger, nodeName string, hostNetwork bool, heartbeatPeriod time.Duration) (types.Exporter, error) {
	agentName := common.NameDaemonSetAgentPodNet
	if hostNetwork {
		agentName = common.NameDaemonSetAgentHostNet
	}

	pco := &problemclient.ProblemClientOptions{
		AgentName:      agentName,
		AgentVersion:   version.Version,
		NodeName:       nodeName,
		EventNamespace: "",
		KubeConfigPath: "", // in-cluster
		Log:            log,
	}
	c, err := problemclient.NewClient(pco)
	if err != nil {
		return nil, err
	}

	ke := k8sExporter{
		log:              log,
		client:           c,
		conditionManager: condition.NewConditionManager(log, c, clock.RealClock{}, heartbeatPeriod),
	}

	ke.conditionManager.Start()

	return &ke, nil
}

func (ke *k8sExporter) ExportProblems(status *types.Status) {
	for _, cdt := range status.Conditions {
		ke.conditionManager.UpdateCondition(cdt)
	}
}
