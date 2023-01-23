// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aggregation

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/aggregation/types"
	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/sirupsen/logrus"
)

type ObsAggregationOptions struct {
	// Log is the used logger
	Log logrus.FieldLogger
	// NodeName is the hostname of this node
	NodeName string
	// ReportPeriod is the period between two reports
	ReportPeriod time.Duration
	// TimeWindow is the window after which aggregations are removed if no new ones are added
	TimeWindow time.Duration
	// LogDirectory is an optional parameter to write the report to (in addition to log output)
	LogDirectory string
	// HostNetwork is true if agent runs on host network
	HostNetwork bool
	// K8sExporterEnabled if true, patches conditions in node status and creates events
	K8sExporterEnabled bool
	// K8sExporterHeartbeatPeriod is the heartbeat period of the K8s exporter
	K8sExporterHeartbeatPeriod time.Duration
}

type obsAggr struct {
	log                     logrus.FieldLogger
	lock                    sync.Mutex
	k8sExporter             types.Exporter
	aggregations            map[jobEdge]*jobEdgeAggregation
	reportPeriod            time.Duration
	timeWindow              time.Duration
	logDirectory            string
	hostNetwork             bool
	validEdges              ValidEdges
	lastReport              time.Time
	lastReportToK8sExporter time.Time
	lastK8sExporterStatus   bool
}

type jobEdge struct {
	jobID    string
	srcHost  string
	destHost string
}

type ValidEdges struct {
	JobIDs    common.StringSet
	SrcHosts  common.StringSet
	DestHosts common.StringSet
}

type ObservationListenerExtended interface {
	nwpd.ObservationListener

	UpdateValidEdges(edges ValidEdges)
}

func (je jobEdge) String() string {
	return fmt.Sprintf("%s->%s[%s]", je.srcHost, je.destHost, je.jobID)
}

type jobEdgeAggregation struct {
	firstTime          time.Time
	totalCount         int
	reportStart        time.Time
	reportOkCount      int
	reportFailureCount int
	okLast             time.Time
	okStrikeFirst      time.Time
	okStrike           int
	failedLast         time.Time
	failedStrikeFirst  time.Time
	failedStrike       int
	lastObs            *nwpd.Observation
}

func (jea *jobEdgeAggregation) IsOKSinceLastReport() bool {
	return jea.reportFailureCount == 0
}

func (jea *jobEdgeAggregation) IsLastOK() bool {
	return jea.okStrike > 0
}

func (jea *jobEdgeAggregation) IsOverdue() bool {
	if jea.IsOKSinceLastReport() && jea.lastObs != nil {
		expectedAt := jea.lastObs.Timestamp.AsTime().Add(jea.lastObs.Period.AsDuration()).Add(10 * time.Second)
		return expectedAt.Before(time.Now())
	}
	return true
}

func (jea *jobEdgeAggregation) Report(je jobEdge, start time.Time) string {
	if jea.IsOKSinceLastReport() {
		msg := fmt.Sprintf("%s: OK", je)
		if jea.lastObs != nil && jea.lastObs.Duration != nil {
			d := jea.lastObs.Duration.AsDuration().Milliseconds()
			msg += fmt.Sprintf(" (%d ms)", d)
		}
		if jea.lastObs != nil && jea.lastObs.Timestamp.AsTime().Before(start) {
			msg += fmt.Sprintf(" last observed: %s", common.FormatAsUTC(jea.lastObs.Timestamp.AsTime()))
		}
		return msg
	}
	seconds := int(time.Now().Sub(jea.reportStart).Seconds())
	return fmt.Sprintf("%s: %d/%d checks failed in last %ds (last ok: %s)", je,
		jea.reportFailureCount, jea.reportFailureCount+jea.reportOkCount, seconds, common.FormatAsUTC(jea.okLast))
}

func (jea *jobEdgeAggregation) add(obs *nwpd.Observation) {
	jea.totalCount++
	jea.lastObs = obs
	if obs.Ok {
		if jea.okLast.Before(jea.failedLast) {
			jea.okStrike = 0
			jea.okStrikeFirst = obs.Timestamp.AsTime()
		}
		jea.okLast = obs.Timestamp.AsTime()
		jea.okStrike++
		jea.reportOkCount++
	} else {
		if jea.failedLast.Before(jea.okLast) {
			jea.failedStrike = 0
			jea.failedStrikeFirst = obs.Timestamp.AsTime()
		}
		jea.failedLast = obs.Timestamp.AsTime()
		jea.failedStrike++
		jea.reportFailureCount++
	}
}

func (jea *jobEdgeAggregation) lastTimestamp() time.Time {
	if jea.okStrike > 0 {
		return jea.okLast
	}
	if jea.failedStrike > 0 {
		return jea.failedLast
	}
	return jea.firstTime
}

type groupCounter struct {
	ok      map[string]int
	unknown map[string]int
	failed  map[string]int
}

func newGroupCounter() *groupCounter {
	return &groupCounter{
		ok:      map[string]int{},
		unknown: map[string]int{},
		failed:  map[string]int{},
	}
}

func (c *groupCounter) inc(key string, ok *bool) {
	if ok == nil {
		c.unknown[key] += 1
	} else if *ok {
		c.ok[key] += 1
	} else {
		c.failed[key] += 1
	}
}

func (c *groupCounter) summary() string {
	var failedNames []string
	for key := range c.failed {
		failedNames = append(failedNames, key)
	}
	sort.Strings(failedNames)
	suffix := ""
	if len(failedNames) > 0 {
		suffix = fmt.Sprintf(" (failed items: %s)", strings.Join(failedNames, ","))
	}
	return fmt.Sprintf("ok/unknown/failed: %d/%d/%d%s", len(c.ok), len(c.unknown), len(c.failed), suffix)
}

type conditionStatus struct {
	conditionType string
	source        string
	network       string
	alerts        map[jobEdge]time.Time
	lastChange    time.Time
}

func newConditionStatus(hostNetwork bool) *conditionStatus {
	typ := "ClusterNetworkProblem"
	source := common.NameDaemonSetAgentPodNet
	network := "cluster"
	if hostNetwork {
		typ = "HostNetworkProblem"
		source = common.NameDaemonSetAgentHostNet
		network = "host"
	}
	return &conditionStatus{conditionType: typ, source: source, network: network, alerts: map[jobEdge]time.Time{}}
}

func (cs *conditionStatus) update(je jobEdge, alerting bool, firstTime time.Time) {
	_, ok := cs.alerts[je]
	if alerting == ok {
		// unchanged
		return
	}

	cs.lastChange = time.Now()
	if alerting {
		cs.alerts[je] = firstTime
	} else {
		delete(cs.alerts, je)
	}
}

func (cs *conditionStatus) report() types.Condition {
	condition := types.Condition{
		Type:       cs.conditionType,
		Status:     types.False,
		Transition: time.Now(),
		Reason:     "NoNetworkProblems",
		Message:    fmt.Sprintf("no %s network problems", cs.network),
		Source:     cs.source,
	}
	if len(cs.alerts) == 0 {
		return condition
	}

	condition.Status = types.True
	condition.Reason = "FailedNetworkChecks"
	jobIDSet := common.StringSet{}
	destHostSet := common.StringSet{}
	count := 0
	for je, firstTime := range cs.alerts {
		if firstTime.Before(condition.Transition) {
			condition.Transition = firstTime
		}
		jobIDSet.Add(je.jobID)
		destHostSet.Add(je.destHost)
		count++
	}
	var details string
	if jobIDSet.Len() == 1 || destHostSet.Len() == 1 {
		details = fmt.Sprintf("jobID/destination combinations: %s/%s", toRestrictedList(jobIDSet, 5), toRestrictedList(destHostSet, 3))
	} else {
		details = fmt.Sprintf("%d pairs of jobIDs %s and destinations %s", count, toRestrictedList(jobIDSet, 5), toRestrictedList(destHostSet, 3))
	}
	condition.Message = fmt.Sprintf("%s network problems for %s", cs.network, details)
	return condition
}

func toRestrictedList(set common.StringSet, max int) string {
	array := set.ToSortedArray()
	if len(array) == 1 {
		return array[0]
	}
	n := len(array)
	if n > max {
		n = max
	}
	s := "(" + strings.Join(array[:n], ",")
	if n < len(array) {
		s += fmt.Sprintf(" and %d more", len(array)-n)
	}
	s += ")"
	return s
}

var _ ObservationListenerExtended = &obsAggr{}

func NewObsAggregator(options *ObsAggregationOptions) (*obsAggr, error) {
	if options.LogDirectory != "" {
		err := os.MkdirAll(options.LogDirectory, 0777)
		if err != nil {
			return nil, err
		}
	}

	var k8sExporter types.Exporter
	if options.K8sExporterEnabled {
		var err error
		k8sExporter, err = newExporter(options.Log, options.NodeName, options.HostNetwork, options.K8sExporterHeartbeatPeriod)
		if err != nil {
			return nil, err
		}
	}

	return &obsAggr{
		log:          options.Log,
		aggregations: map[jobEdge]*jobEdgeAggregation{},
		lastReport:   time.Now(),
		reportPeriod: options.ReportPeriod,
		timeWindow:   options.TimeWindow,
		logDirectory: options.LogDirectory,
		hostNetwork:  options.HostNetwork,
		k8sExporter:  k8sExporter,
	}, nil
}

func (a *obsAggr) UpdateValidEdges(edges ValidEdges) {
	a.lock.Lock()
	defer a.lock.Unlock()

	a.validEdges = edges
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
		go a.report()
		a.lastReport = time.Now()
	}
}

type reportOptions struct {
	fullReport               bool
	hostNetwork              bool
	conditionMinFailureCount int
	conditionMinTimeWindow   time.Duration
}

type reportData struct {
	options     *reportOptions
	start       time.Time
	end         time.Time
	jobCounter  *groupCounter
	srcCounter  *groupCounter
	destCounter *groupCounter
	noissues    []string
	issues      []string
	status      *conditionStatus
}

func newReportData(start, end time.Time, options *reportOptions) *reportData {
	return &reportData{
		options:     options,
		start:       start,
		end:         end,
		jobCounter:  newGroupCounter(),
		srcCounter:  newGroupCounter(),
		destCounter: newGroupCounter(),
		status:      newConditionStatus(options.hostNetwork),
	}
}

func (r *reportData) add(je jobEdge, aggr *jobEdgeAggregation) {
	var ok *bool
	if aggr.reportFailureCount != 0 || aggr.reportOkCount != 0 {
		good := aggr.reportFailureCount == 0
		ok = &good
		r.updateStatus(je, aggr)
	}
	r.jobCounter.inc(je.jobID, ok)
	r.srcCounter.inc(je.srcHost, ok)
	r.destCounter.inc(je.destHost, ok)
	if ok != nil && !*ok {
		r.issues = append(r.issues, aggr.Report(je, r.start))
	} else if r.options.fullReport || ok == nil {
		if r.options.fullReport || aggr.IsOverdue() {
			r.noissues = append(r.noissues, aggr.Report(je, r.start))
		}
	}
}

func (r *reportData) updateStatus(je jobEdge, aggr *jobEdgeAggregation) {
	alerting := aggr.reportFailureCount > 0 &&
		aggr.failedStrike >= r.options.conditionMinFailureCount &&
		aggr.failedLast.Sub(aggr.failedStrikeFirst) > r.options.conditionMinTimeWindow
	r.status.update(je, alerting, aggr.failedStrikeFirst)
}

func (r *reportData) sort() {
	sort.Strings(r.issues)
	sort.Strings(r.noissues)
}

func (r *reportData) summary() []string {
	return []string{
		fmt.Sprintf("Jobs: %s", r.jobCounter.summary()),
		fmt.Sprintf("SourceHost: %s", r.srcCounter.summary()),
		fmt.Sprintf("DestHost: %s", r.destCounter.summary()),
	}
}

func (a *obsAggr) report() {
	options := &reportOptions{
		fullReport:               false,
		hostNetwork:              a.hostNetwork,
		conditionMinFailureCount: 2,
		conditionMinTimeWindow:   3 * time.Minute,
	}
	report := a.calcReport(options, true)
	report.sort()
	a.reportToLog(report)
	a.reportToFilesystem(report)
	a.reportToK8sExporter(report)
}

func (a *obsAggr) reportToLog(report *reportData) {
	prefix := "Report: "
	for _, s := range report.noissues {
		a.log.Info(prefix + s)
	}
	for _, s := range report.issues {
		a.log.Warn(prefix + s)
	}
	for _, s := range report.summary() {
		a.log.Info(prefix + s)
	}
}

func (a *obsAggr) reportToFilesystem(report *reportData) {
	if a.logDirectory == "" {
		return
	}

	name := common.NameDaemonSetAgentPodNet
	if report.options.hostNetwork {
		name = common.NameDaemonSetAgentHostNet
	}
	filename := path.Join(a.logDirectory, name+".log")
	info, err := os.Stat(filename)
	if err != nil && !os.IsNotExist(err) {
		a.log.Warnf("cannot write log to %s: %s", filename, err)
		return
	}
	if err == nil && info.Size() > common.MaxLogfileSize {
		old := filename + ".old"
		_ = os.Remove(old)
		err := os.Rename(filename, old)
		if err != nil {
			a.log.Warnf("cannot rename %s to %s: %s", filename, old, err)
		}
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		a.log.Warnf("cannot open %s: %s", filename, err)
		return
	}
	defer f.Close()

	prefix := time.Now().UTC().Format("2006-01-02T15:04:05Z ")
	for _, s := range report.issues {
		f.WriteString(prefix)
		f.WriteString(s)
		f.WriteString("\n")
	}
	for _, s := range report.summary() {
		f.WriteString(prefix)
		f.WriteString(s)
		f.WriteString("\n")
	}
}

func (a *obsAggr) reportToK8sExporter(report *reportData) {
	if a.k8sExporter == nil {
		return
	}

	condition := report.status.report()
	a.k8sExporter.ExportProblems(&types.Status{
		Conditions: []types.Condition{condition},
	})
}

func (a *obsAggr) calcReport(options *reportOptions, resetCount bool) *reportData {
	a.lock.Lock()
	defer a.lock.Unlock()

	end := time.Now()
	start := end.Add(-1 * a.reportPeriod)
	outdated := end.Add(-1 * a.timeWindow)
	report := newReportData(start, end, options)
	for je, aggr := range a.aggregations {
		if !a.isValidEdge(je) {
			delete(a.aggregations, je)
			continue
		}
		if aggr.lastTimestamp().Before(outdated) {
			delete(a.aggregations, je)
		}
		report.add(je, aggr)
		if resetCount {
			aggr.reportOkCount = 0
			aggr.reportFailureCount = 0
		}
	}
	return report
}

func (a *obsAggr) isValidEdge(je jobEdge) bool {
	if a.validEdges.JobIDs.Len() == 0 &&
		a.validEdges.SrcHosts.Len() == 0 &&
		a.validEdges.DestHosts.Len() == 0 {
		return true
	}

	if !a.validEdges.JobIDs.Contains(je.jobID) {
		return false
	}
	if !a.validEdges.SrcHosts.Contains(je.srcHost) {
		return false
	}
	if !a.validEdges.DestHosts.Contains(je.destHost) {
		return false
	}
	return true
}
