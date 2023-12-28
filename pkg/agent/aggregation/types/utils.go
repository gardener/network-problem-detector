/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package types

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConvertToAPICondition converts the internal node condition to corev1.NodeCondition.
func ConvertToAPICondition(condition Condition) corev1.NodeCondition {
	return corev1.NodeCondition{
		Type:               corev1.NodeConditionType(condition.Type),
		Status:             ConvertToAPIConditionStatus(condition.Status),
		LastTransitionTime: ConvertToAPITimestamp(condition.Transition),
		Reason:             condition.Reason,
		Message:            condition.Message,
	}
}

// ConvertToAPIConditionStatus converts the internal node condition status to corev1.ConditionStatus.
func ConvertToAPIConditionStatus(status ConditionStatus) corev1.ConditionStatus {
	switch status {
	case True:
		return corev1.ConditionTrue
	case False:
		return corev1.ConditionFalse
	case Unknown:
		return corev1.ConditionUnknown
	default:
		panic("unknown condition status")
	}
}

// ConvertToAPIEventType converts the internal severity to event type.
func ConvertToAPIEventType(severity Severity) string {
	switch severity {
	case Info:
		return corev1.EventTypeNormal
	case Warn:
		return corev1.EventTypeWarning
	default:
		// Should never get here, just in case
		return corev1.EventTypeNormal
	}
}

// ConvertToAPITimestamp converts the timestamp to metav1.Time.
func ConvertToAPITimestamp(timestamp time.Time) metav1.Time {
	return metav1.NewTime(timestamp)
}
