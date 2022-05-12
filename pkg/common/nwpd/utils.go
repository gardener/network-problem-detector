// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package nwpd

import (
	"sort"
	"time"
)

type ObservationListener interface {
	Add(obs *Observation)
}

type ListObservationsOptions struct {
	Start           time.Time
	End             time.Time
	Limit           int
	FilterJobIDs    []string
	FilterSrcHosts  []string
	FilterDestHosts []string
	FailuresOnly    bool
}

type ObservationWriter interface {
	ObservationListener
	Run()
	Stop()
	ListObservations(options ListObservationsOptions) (Observations, error)
}

type Observations []*Observation

var _ sort.Interface = Observations{}

func (o Observations) Len() int {
	return len(o)
}

func (o Observations) Less(i, j int) bool {
	ti := o[i].Timestamp.AsTime()
	tj := o[j].Timestamp.AsTime()
	return ti.Before(tj)
}

func (o Observations) Swap(i, j int) {
	h := o[i]
	o[i] = o[j]
	o[j] = h
}
