// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package nwpd

import (
	"math/rand"
	"sort"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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

func CloneAndShuffleNodes(items []Node) []Node {
	if len(items) == 0 {
		return nil
	}
	clone := make([]Node, len(items))
	copy(clone, items)
	rand.Shuffle(len(clone), func(i, j int) { clone[i], clone[j] = clone[j], clone[i] })
	return clone
}

func CloneAndShufflePodEndpoints(items []PodEndpoint) []PodEndpoint {
	if len(items) == 0 {
		return nil
	}
	clone := make([]PodEndpoint, len(items))
	copy(clone, items)
	rand.Shuffle(len(clone), func(i, j int) { clone[i], clone[j] = clone[j], clone[i] })
	return clone
}

func CloneAndShuffleEndpoints(items []Endpoint) []Endpoint {
	if len(items) == 0 {
		return nil
	}
	clone := make([]Endpoint, len(items))
	copy(clone, items)
	rand.Shuffle(len(clone), func(i, j int) { clone[i], clone[j] = clone[j], clone[i] })
	return clone
}

func CloneAndShuffleStrings(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	clone := make([]string, len(list))
	copy(clone, list)
	rand.Shuffle(len(clone), func(i, j int) { clone[i], clone[j] = clone[j], clone[i] })
	return clone
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
