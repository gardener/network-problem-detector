// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aggregation

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/sirupsen/logrus"
)

type obsAggr struct {
	log          logrus.FieldLogger
	lock         sync.Mutex
	aggregations map[jobEdge]*jobEdgeAggregation
	reportPeriod time.Duration
	timeWindow   time.Duration
	lastReport   time.Time
}

type jobEdge struct {
	jobID    string
	srcHost  string
	destHost string
}

func (je jobEdge) String() string {
	return fmt.Sprintf("%s->%s[%s]", je.srcHost, je.destHost, je.jobID)
}

type jobEdgeAggregation struct {
	firstTime       time.Time
	totalCount      int
	reportStart     time.Time
	reportGoodCount int
	reportBadCount  int
	goodLast        time.Time
	goodStrike      int
	badLast         time.Time
	badStrike       int
	lastObs         *nwpd.Observation
}

func (jea *jobEdgeAggregation) IsOKSinceLastReport() bool {
	return jea.reportBadCount == 0
}

func (jea *jobEdgeAggregation) IsLastOK() bool {
	return jea.goodStrike > 0
}

func (jea *jobEdgeAggregation) Report(je jobEdge) string {
	if jea.IsOKSinceLastReport() {
		msg := fmt.Sprintf("%s: OK", je)
		if jea.lastObs != nil && jea.lastObs.Duration != nil {
			d := jea.lastObs.Duration.AsDuration().Milliseconds()
			msg += fmt.Sprintf(" (%d ms)", d)
		}
		return msg
	}
	seconds := int(time.Now().Sub(jea.reportStart).Seconds())
	return fmt.Sprintf("%s: %d/%d checks failed in last %ds (last good: %s)", je,
		jea.reportBadCount, jea.reportBadCount+jea.reportGoodCount, seconds, utctime(jea.goodLast))
}

func (jea *jobEdgeAggregation) add(obs *nwpd.Observation) {
	jea.totalCount++
	jea.lastObs = obs
	if obs.Ok {
		if jea.goodLast.Before(jea.badLast) {
			jea.goodStrike = 0
		}
		jea.goodLast = obs.Timestamp.AsTime()
		jea.goodStrike++
		jea.reportGoodCount++
	} else {
		if jea.badLast.Before(jea.goodLast) {
			jea.badStrike = 0
		}
		jea.badLast = obs.Timestamp.AsTime()
		jea.badStrike++
		jea.reportBadCount++
	}
}

func (jea *jobEdgeAggregation) lastTimestamp() time.Time {
	if jea.goodStrike > 0 {
		return jea.goodLast
	}
	if jea.badStrike > 0 {
		return jea.badLast
	}
	return jea.firstTime
}

type groupCounter struct {
	good    map[string]int
	unknown map[string]int
	bad     map[string]int
}

func newGroupCounter() *groupCounter {
	return &groupCounter{
		good:    map[string]int{},
		unknown: map[string]int{},
		bad:     map[string]int{},
	}
}

func (c *groupCounter) inc(key string, ok *bool) {
	if ok == nil {
		c.unknown[key] += 1
	} else if *ok {
		c.good[key] += 1
	} else {
		c.bad[key] += 1
	}
}

func (c *groupCounter) summary() string {
	var bad []string
	for key := range c.bad {
		bad = append(bad, key)
	}
	sort.Strings(bad)
	suffix := ""
	if len(bad) > 0 {
		suffix = fmt.Sprintf(" (failed items: %s)", strings.Join(bad, ","))
	}
	return fmt.Sprintf("good/unknown/bad: %d/%d/%d%s", len(c.good), len(c.unknown), len(c.bad), suffix)
}

var _ nwpd.ObservationListener = &obsAggr{}

func NewObsAggregator(log logrus.FieldLogger, reportPeriod, timeWindow time.Duration) *obsAggr {
	return &obsAggr{
		log:          log,
		aggregations: map[jobEdge]*jobEdgeAggregation{},
		lastReport:   time.Now(),
		reportPeriod: reportPeriod,
		timeWindow:   timeWindow,
	}
}

func (a *obsAggr) Add(obs *nwpd.Observation) {
	a.lock.Lock()
	defer a.lock.Unlock()

	je := jobEdge{jobID: obs.JobID, srcHost: obs.SrcHost, destHost: obs.DestHost}
	jea := a.aggregations[je]
	if jea == nil {
		jea = &jobEdgeAggregation{
			firstTime:   obs.Timestamp.AsTime(),
			reportStart: obs.Timestamp.AsTime(),
		}
		a.aggregations[je] = jea
	}

	jea.add(obs)

	if a.lastReport.Add(a.reportPeriod).Before(time.Now()) {
		go a.reportToLog()
		a.lastReport = time.Now()
	}
}

type reportData struct {
	fullReport  bool
	timestamp   time.Time
	jobCounter  *groupCounter
	srcCounter  *groupCounter
	destCounter *groupCounter
	issues      []string
}

func newReportData(fullReport bool) *reportData {
	return &reportData{
		fullReport:  fullReport,
		timestamp:   time.Now(),
		jobCounter:  newGroupCounter(),
		srcCounter:  newGroupCounter(),
		destCounter: newGroupCounter(),
	}
}

func (r *reportData) add(je jobEdge, aggr *jobEdgeAggregation) {
	var ok *bool
	if aggr.reportBadCount != 0 || aggr.reportGoodCount != 0 {
		good := aggr.reportBadCount == 0
		ok = &good
	}
	r.jobCounter.inc(je.jobID, ok)
	r.srcCounter.inc(je.srcHost, ok)
	r.destCounter.inc(je.destHost, ok)
	if r.fullReport || ok == nil || !*ok {
		r.issues = append(r.issues, aggr.Report(je))
	}
}

func (r *reportData) sort() {
	sort.Strings(r.issues)
}

func (r *reportData) summary() []string {
	return []string{
		fmt.Sprintf("Jobs: %s", r.jobCounter.summary()),
		fmt.Sprintf("SourceHost: %s", r.srcCounter.summary()),
		fmt.Sprintf("DestHost: %s", r.destCounter.summary()),
	}
}

func (a *obsAggr) reportToLog() {
	report := a.calcReport(false, true)
	report.sort()
	for _, s := range report.issues {
		a.log.Warn(s)
	}
	for _, s := range report.summary() {
		a.log.Info(s)
	}
}

func (a *obsAggr) calcReport(fullReport, resetCount bool) *reportData {
	a.lock.Lock()
	defer a.lock.Unlock()

	outdated := time.Now().Add(-1 * a.timeWindow)
	report := newReportData(fullReport)
	for je, aggr := range a.aggregations {
		if aggr.lastTimestamp().Before(outdated) {
			delete(a.aggregations, je)
		}
		report.add(je, aggr)
		if resetCount {
			aggr.reportGoodCount = 0
			aggr.reportBadCount = 0
		}
	}
	return report
}

func utctime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
