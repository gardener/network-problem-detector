// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ToIntObservation(obs *nwpd.Observation, idMap *StringIdMap, persistor IntStringPersistor) (*nwpd.IntObservation, error) {
	is, err := idMap.GetKey(persistor, obs.SrcHost)
	if err != nil {
		return nil, err
	}
	id, err := idMap.GetKey(persistor, obs.DestHost)
	if err != nil {
		return nil, err
	}
	ij, err := idMap.GetKey(persistor, obs.JobID)
	if err != nil {
		return nil, err
	}
	return &nwpd.IntObservation{
		SrcHost:        is,
		DestHost:       id,
		JobID:          ij,
		Ok:             obs.Ok,
		TimeMillis:     obs.Timestamp.AsTime().UnixMilli(),
		DurationMillis: int32(obs.Duration.AsDuration().Milliseconds()),
		PeriodMillis:   int32(obs.Period.AsDuration().Milliseconds()),
	}, nil
}

func IntObsToObservation(o *nwpd.IntObservation, idMap *StringIdMap) (*nwpd.Observation, error) {
	ss, err := idMap.GetValue(o.SrcHost)
	if err != nil {
		return nil, err
	}
	sd, err := idMap.GetValue(o.DestHost)
	if err != nil {
		return nil, err
	}
	sj, err := idMap.GetValue(o.JobID)
	if err != nil {
		return nil, err
	}
	var duration, period *durationpb.Duration
	if o.DurationMillis > 0 {
		duration = durationpb.New(time.Millisecond * time.Duration(o.DurationMillis))
	}
	if o.PeriodMillis > 0 {
		period = durationpb.New(time.Millisecond * time.Duration(o.PeriodMillis))
	}
	return &nwpd.Observation{
		JobID:     sj,
		SrcHost:   ss,
		DestHost:  sd,
		Timestamp: timestamppb.New(time.UnixMilli(o.TimeMillis)),
		Duration:  duration,
		Ok:        o.Ok,
		Period:    period,
	}, nil
}

func IntObsToBytes(o *nwpd.IntObservation) ([]byte, error) {
	return proto.Marshal(o)
}

func IntObsFromBytes(value []byte) (*nwpd.IntObservation, error) {
	intobs := &nwpd.IntObservation{}
	err := proto.Unmarshal(value, intobs)
	if err != nil {
		return nil, err
	}
	return intobs, nil
}
