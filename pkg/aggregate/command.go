// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aggregate

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/db"
	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	svg "github.com/ajstarks/svgo"
	"github.com/jamiealquiza/tachymeter"
	"github.com/spf13/cobra"
)

type aggrCommand struct {
	directory         string
	minutes           int
	buckets           int
	openMetricsOutput string
	svgOutput         string
	start             string
	end               string
	jobFilter         string
	srcFilter         string
	destFilter        string

	jobFilterPattern  *regexp.Regexp
	srcFilterPattern  *regexp.Regexp
	destFilterPattern *regexp.Regexp
}

type edge struct {
	src  string
	dest string
}

type edgeData struct {
	jobResults map[string]*results
}

type results struct {
	bucketsData      []*bucketData
	lastOkMillis     int64
	lastFailedMillis int64
	count            int
	cumulativeDelta  int64
	tachy            *tachymeter.Tachymeter
}

type bucketData struct {
	okCount            uint16
	failedCount        uint16
	durationCumulative time.Duration
	minDuration        time.Duration
	maxDuration        time.Duration
}

func (r *results) incr(bucket int, ok bool, duration time.Duration) {
	bd := r.bucketsData[bucket]
	if bd == nil {
		bd = &bucketData{}
		r.bucketsData[bucket] = bd
	}
	if ok {
		bd.durationCumulative += duration
		if bd.okCount == 0 || bd.minDuration > duration {
			bd.minDuration = duration
		}
		if bd.okCount == 0 || bd.maxDuration < duration {
			bd.maxDuration = duration
		}
		bd.okCount++
	} else {
		bd.failedCount++
	}
}

func CreateAggregateCmd() *cobra.Command {
	ac := &aggrCommand{}
	cmd := &cobra.Command{
		Use:     "aggr",
		Aliases: []string{"aggregate"},
		Short:   "aggregate observations",
		RunE:    ac.aggr,
	}
	cmd.Flags().StringVar(&ac.directory, "input", "collected-observations", "database directory to load the collected observations.")
	cmd.Flags().IntVar(&ac.minutes, "minutes", 60, "restrict aggregation to given last minutes.")
	cmd.Flags().IntVar(&ac.buckets, "buckets", 60, "number of histogram buckets.")
	cmd.Flags().StringVar(&ac.openMetricsOutput, "open-metrics-output", "", "optional file name for Open Metrics output (used for import to prometheus)")
	cmd.Flags().StringVar(&ac.svgOutput, "svg-output", "", "optional file name for SVG output")
	cmd.Flags().StringVar(&ac.start, "start", "", "start timestamp (e.g. format '2022-01-23T23:49:11' or '23:49:11')")
	cmd.Flags().StringVar(&ac.end, "end", "", "end timestamp (e.g. format '2022-01-23T23:49:11' or '23:49:11')")
	cmd.Flags().StringVar(&ac.jobFilter, "job", "", "filter observations by job id (use '*' for globbing)")
	cmd.Flags().StringVar(&ac.srcFilter, "src", "", "filter observations by source (use '*' for globbing)")
	cmd.Flags().StringVar(&ac.destFilter, "dest", "", "filter observations by destination (use '*' for globbing)")
	return cmd
}

func (ac *aggrCommand) aggr(_ *cobra.Command, _ []string) error {
	filenames, err := db.GetAnyRecordFiles(ac.directory, true)
	if err != nil {
		return err
	}

	if err := ac.prepareFilterExpressions(); err != nil {
		return err
	}

	endMillis := time.Now().UnixMilli()
	startMillis := endMillis - int64(ac.minutes*60000)

	if ac.end != "" {
		endMillis, err = parseTimestamp(ac.end)
		if err != nil {
			return err
		}
		startMillis = endMillis - int64(ac.minutes*60000)
	}
	if ac.start != "" {
		startMillis, err = parseTimestamp(ac.start)
		if err != nil {
			return err
		}
		if ac.end == "" {
			endMillis = startMillis + int64(ac.minutes*60000)
		}
	}
	if startMillis >= endMillis {
		return fmt.Errorf("invalid time range")
	}

	fmt.Printf("%s - %s with %d buckets\n",
		time.UnixMilli(startMillis).UTC().Format("2006-01-02T15:04:05Z"),
		time.UnixMilli(endMillis).UTC().Format("2006-01-02T15:04:05Z"),
		ac.buckets)
	bucketMillis := (endMillis - startMillis) / int64(ac.buckets)
	data := map[edge]*edgeData{}
	count := 0
	var dataStartMillis, dataEndMillis int64

	for _, filename := range filenames {
		err := db.IterateRecordFile(filename, func(obs *nwpd.Observation) error {
			timeMillis := obs.Timestamp.AsTime().UnixMilli()

			if dataStartMillis == 0 || dataStartMillis > timeMillis {
				dataStartMillis = timeMillis
			}
			if dataEndMillis < timeMillis {
				dataEndMillis = timeMillis
			}
			if timeMillis < startMillis || timeMillis > endMillis {
				return nil
			}
			count++

			if filtered(obs.SrcHost, ac.srcFilterPattern) {
				return nil
			}
			if filtered(obs.DestHost, ac.destFilterPattern) {
				return nil
			}
			if filtered(obs.JobID, ac.jobFilterPattern) {
				return nil
			}

			edge := edge{
				src:  obs.SrcHost,
				dest: obs.DestHost,
			}
			ed := data[edge]
			if ed == nil {
				ed = &edgeData{
					jobResults: map[string]*results{},
				}
				data[edge] = ed
			}
			jr := ed.jobResults[obs.JobID]
			if jr == nil {
				jr = &results{
					bucketsData: make([]*bucketData, ac.buckets),
					tachy:       tachymeter.New(&tachymeter.Config{Size: 20}),
				}
				ed.jobResults[obs.JobID] = jr
			}
			aggrBucket := int((timeMillis - startMillis) * int64(ac.buckets) / (endMillis - startMillis))
			jr.incr(aggrBucket, obs.Ok, obs.Duration.AsDuration())
			last := jr.lastOkMillis
			if jr.lastFailedMillis > last {
				last = jr.lastFailedMillis
			}
			if last > 0 {
				jr.cumulativeDelta += timeMillis - last
				jr.count++
			}
			if obs.Ok {
				jr.lastOkMillis = timeMillis
				if obs.Duration != nil {
					jr.tachy.AddTime(obs.Duration.AsDuration())
				}
			} else {
				jr.lastFailedMillis = timeMillis
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	jobs := common.StringSet{}
	srcNodes := common.StringSet{}
	destNodes := common.StringSet{}
	for e, ed := range data {
		srcNodes.Add(e.src)
		destNodes.Add(e.dest)
		for jobID := range ed.jobResults {
			jobs.Add(jobID)
		}
	}
	sortedJobs := jobs.ToSortedArray()
	sortedSrcNodes := srcNodes.ToSortedArray()
	sortedDestNodes := destNodes.ToSortedArray()
	for _, jobID := range sortedJobs {
		fmt.Printf("Job: %s\n", jobID)
		for _, src := range sortedSrcNodes {
			for _, dest := range sortedDestNodes {
				ed := data[edge{
					src:  src,
					dest: dest,
				}]
				if ed != nil {
					jr := ed.jobResults[jobID]
					if jr != nil {
						ac.printJobResultLine(src, dest, jr)
					}
				}
			}
		}
		fmt.Printf("\n")
	}
	if ac.openMetricsOutput != "" {
		err = ac.writeOpenMetricsFile(sortedJobs, sortedSrcNodes, sortedDestNodes, startMillis/1000, bucketMillis, data)
		if err != nil {
			return err
		}
	}
	if ac.svgOutput != "" {
		err = ac.writeSVGFile(sortedJobs, sortedSrcNodes, sortedDestNodes, data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ac *aggrCommand) prepareFilterExpressions() error {
	var err error
	if ac.jobFilterPattern, err = buildFilter(ac.jobFilter); err != nil {
		return err
	}
	if ac.srcFilterPattern, err = buildFilter(ac.srcFilter); err != nil {
		return err
	}
	if ac.destFilterPattern, err = buildFilter(ac.destFilter); err != nil {
		return err
	}
	return nil
}

func (ac *aggrCommand) printJobResultLine(src, dest string, jr *results) {
	var sb strings.Builder
	for i := 0; i < ac.buckets; i++ {
		bd := jr.bucketsData[i]
		switch {
		case bd == nil || (bd.okCount == 0 && bd.failedCount == 0):
			sb.WriteString(" ")
		case bd.failedCount == 0:
			sb.WriteString(".")
		case bd.okCount < bd.failedCount:
			sb.WriteString("E")
		default:
			sb.WriteString("e")
		}
	}
	latence := ""
	if jr.count > 0 {
		metrics := jr.tachy.Calc()
		if metrics.Time.P95.Milliseconds() > 0 {
			latence = fmt.Sprintf(" (period=%.1f s, min/mean/p95=%d/%d/%d ms)", float64(jr.cumulativeDelta)/float64(jr.count)/1000,
				metrics.Time.Min.Milliseconds(), metrics.Time.HMean.Milliseconds(), metrics.Time.P95.Milliseconds())
		} else {
			latence = fmt.Sprintf(" (period=%.1f s)", float64(jr.cumulativeDelta)/float64(jr.count)/1000)
		}
	}
	fmt.Printf("%s -> %s: %s%s\n", src, dest, sb.String(), latence)
}

func (ac *aggrCommand) writeOpenMetricsFile(jobs, srcNodes, destNodes []string, startUnixSecs, bucketMillis int64, data map[edge]*edgeData) error {
	f, err := os.OpenFile(ac.openMetricsOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o750) //  #nosec G302 -- no sensitive data
	if err != nil {
		return err
	}
	defer f.Close()
	err = ac.writeMetrics(f, "nwpd_aggregation_counter", "gauge",
		"The number of ok or failed checks per aggregated bucket with labels source, destination, jobID, success.",
		jobs, srcNodes, destNodes, data, startUnixSecs, bucketMillis,
		func(w io.StringWriter, name, src, dest, jobID string, bd *bucketData, t int64) error {
			if bd.okCount > 0 {
				if _, err := w.WriteString(fmt.Sprintf("%s{src=%q,dest=%q,job=%q,status=\"ok\"} %d %d\n",
					name, src, dest, jobID, bd.okCount, t)); err != nil {
					return err
				}
			}
			if bd.failedCount > 0 {
				if _, err := w.WriteString(fmt.Sprintf("%s{src=%q,dest=%q,job=%q,status=\"failed\"} %d %d\n",
					name, src, dest, jobID, bd.failedCount, t)); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}
	err = ac.writeMetrics(f, "nwpd_aggregation_latence_ms", "gauge",
		"The mean latence per aggregated bucket with labels source, destination, jobID.",
		jobs, srcNodes, destNodes, data, startUnixSecs, bucketMillis,
		func(w io.StringWriter, name, src, dest, jobID string, bd *bucketData, t int64) error {
			if bd.okCount > 0 {
				d := (bd.durationCumulative / time.Duration(bd.okCount)).Milliseconds()
				if _, err := w.WriteString(fmt.Sprintf("%s{src=%q,dest=%q,job=%q,value=\"mean\"} %d %d\n",
					name, src, dest, jobID, d, t)); err != nil {
					return err
				}
				if _, err := w.WriteString(fmt.Sprintf("%s{src=%q,dest=%q,job=%q,value=\"min\"} %d %d\n",
					name, src, dest, jobID, bd.minDuration.Milliseconds(), t)); err != nil {
					return err
				}
				if _, err := w.WriteString(fmt.Sprintf("%s{src=%q,dest=%q,job=%q,value=\"max\"} %d %d\n",
					name, src, dest, jobID, bd.maxDuration.Milliseconds(), t)); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}
	_, err = f.WriteString("# EOF")
	return err
}

func (ac *aggrCommand) writeMetrics(f *os.File, name, metricsType, description string,
	jobs, srcNodes, destNodes []string, data map[edge]*edgeData, startUnixSecs, bucketMillis int64,
	linePrinter func(w io.StringWriter, name, src, dest, jobId string, bd *bucketData, t int64) error,
) error {
	var err error
	_, err = f.WriteString(fmt.Sprintf("# HELP %s %s\n", name, description))
	if err != nil {
		return err
	}
	_, err = f.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, metricsType))
	if err != nil {
		return err
	}
	for _, src := range srcNodes {
		for _, dest := range destNodes {
			ed := data[edge{
				src:  src,
				dest: dest,
			}]
			if ed == nil {
				continue
			}
			for _, jobID := range jobs {
				jr := ed.jobResults[jobID]
				if jr != nil {
					for i := 0; i < ac.buckets; i++ {
						bd := jr.bucketsData[i]
						if bd != nil {
							t := startUnixSecs + (bucketMillis*int64(i)+bucketMillis/2)/1000
							if err := linePrinter(f, name, src, dest, jobID, bd, t); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (ac *aggrCommand) writeSVGFile(jobs, srcNodes, destNodes []string, data map[edge]*edgeData) error {
	f, err := os.OpenFile(ac.svgOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o750) //  #nosec G302 -- no sensitive data
	if err != nil {
		return err
	}
	defer f.Close()

	for _, s := range []string{
		"<!DOCTYPE html>\n<html>\n",
		"<head>\n",
		"<style>\n",
		"svg text.hover {display: none; text-anchor:middle; font-size:5px; font-family:sans-serif;}\n",
		"svg g:hover text.hover {display: block;}\n",
		"svg g:hover rect {fill: rgb(255,128,255)!important;}\n",
		"</style>\n",
		"</head>\n",
		"<body>\n",
	} {
		_, err = f.WriteString(s)
		if err != nil {
			return err
		}
	}

	top := 300
	left := 300
	bucketWidth := ac.buckets + 2
	height := top + 10*len(srcNodes)
	width := left + bucketWidth*len(destNodes)
	canvas := svg.New(f)
	canvas.Start(width, height)
	for id, dest := range destNodes {
		x0 := left + id*bucketWidth
		canvas.Text(x0+bucketWidth/2, top-5, dest, "text-anchor:end;font-size:10px;font-family:sans-serif;writing-mode:tb;")
		canvas.Line(x0, 0, x0, height, "stroke:black")
	}
	for is, src := range srcNodes {
		y0 := top + is*10
		canvas.Text(left-5, y0+9, src, "text-anchor:end;font-size:10px;font-family:sans-serif;")
		canvas.Line(0, y0, width, y0, "stroke:black")
		for id, dest := range destNodes {
			ed := data[edge{
				src:  src,
				dest: dest,
			}]
			if ed == nil {
				continue
			}
			for i := 0; i < ac.buckets; i++ {
				x := left + id*bucketWidth + i + 1
				badJobs := common.StringSet{}
				var okCount, failedCount int
				for _, jobID := range jobs {
					jr := ed.jobResults[jobID]
					if jr != nil {
						bd := jr.bucketsData[i]
						if bd != nil {
							okCount += int(bd.okCount)
							failedCount += int(bd.failedCount)
							if bd.failedCount > 0 {
								badJobs.Add(jobID)
							}
						}
					}
				}
				if okCount > 0 {
					canvas.Rect(x, y0+1, 1, 4, "fill: green; fill-opacity: .85;")
				}
				if failedCount > 0 {
					canvas.Group()
					canvas.Rect(x, y0+5, 1, 4, "fill: red; fill-opacity: .85;")
					label := strings.Join(badJobs.ToSortedArray(), ", ")
					text := fmt.Sprintf(`<text class="hover" x="%d" y="%d">`, x, y0+8)
					_, _ = canvas.Writer.(io.StringWriter).WriteString(text)
					xml.Escape(canvas.Writer, []byte(label))
					_, _ = canvas.Writer.(io.StringWriter).WriteString("</text>")
					canvas.Gend()
				}
			}
		}
	}
	canvas.End()

	_, err = f.WriteString("</body>\n</html>\n")
	return err
}

// parseTimestamp parses a timestamp and returns time in Unix millis.
func parseTimestamp(value string) (int64, error) {
	location := time.Now().Location()
	input := value
	if len(value) < 15 {
		input = time.Now().Format("2006-01-02T") + value
	}
	supportedLayouts := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z07",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05-07",
		"2006-01-02T15:04:05MST",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04Z07:00",
		"2006-01-02T15:04Z07",
		"2006-01-02T15:04-07:00",
		"2006-01-02T15:04-07",
		"2006-01-02T15:04MST",
		"2006-01-02T15:04",
	}
	for _, layout := range supportedLayouts {
		t, err := time.ParseInLocation(layout, input, location)
		if err == nil {
			return t.Local().UnixMilli(), nil
		}
	}
	supported := strings.Join(supportedLayouts, ", ")
	supported2 := strings.ReplaceAll(supported, "2006-01-02T", "")
	return 0, fmt.Errorf("invalid time stamp format: %s (Supported formats are: %s, %s)", value, supported, supported2)
}

func buildFilter(filter string) (*regexp.Regexp, error) {
	if filter == "" {
		return nil, nil
	}
	return regexp.Compile("^" + strings.ReplaceAll(filter, "*", ".*") + "$")
}

func filtered(value string, pattern *regexp.Regexp) bool {
	if pattern == nil {
		return false
	}
	return !pattern.MatchString(value)
}
