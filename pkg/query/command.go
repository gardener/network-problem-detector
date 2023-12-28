// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"fmt"
	"strings"
	"time"

	"github.com/gardener/network-problem-detector/pkg/agent/db"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/spf13/cobra"
)

type queryCommand struct {
	directory  string
	src        string
	dest       string
	jobID      string
	minutes    int
	failedOnly bool
	exactMatch bool
}

func CreateQueryCmd() *cobra.Command {
	qc := &queryCommand{}
	cmd := &cobra.Command{
		Use:   "query",
		Short: "query observations from stored records",
		Long:  `query observations from stored records in the input directory (either downloaded with collect or directly on the node)`,
		RunE:  qc.query,
	}
	cmd.Flags().StringVar(&qc.directory, "input", "collected-observations", "database directory to load the collected observations.")
	cmd.Flags().StringVar(&qc.src, "src", "", "filter by source.")
	cmd.Flags().StringVar(&qc.dest, "dest", "", "filter by dest.")
	cmd.Flags().StringVar(&qc.jobID, "job", "", "filter by job ID.")
	cmd.Flags().BoolVar(&qc.failedOnly, "failed-only", false, "if only failed checks should be printed.")
	cmd.Flags().BoolVar(&qc.exactMatch, "match-exact", false, "if filter expressions must match full names.")
	cmd.Flags().IntVar(&qc.minutes, "minutes", 0, "restrict to given last minutes.")

	return cmd
}

func (qc *queryCommand) query(_ *cobra.Command, _ []string) error {
	filenames, err := db.GetAnyRecordFiles(qc.directory, true)
	if err != nil {
		return err
	}

	var (
		endMillis   = time.Now().UnixMilli()
		startMillis int64
	)
	if qc.minutes > 0 {
		startMillis = endMillis - int64(qc.minutes*60000)
	}
	count := 0
	for _, filename := range filenames {
		if err := db.IterateRecordFile(filename, func(obs *nwpd.Observation) error {
			timeMillis := obs.Timestamp.AsTime().UnixMilli()

			if timeMillis < startMillis || timeMillis > endMillis {
				return nil
			}

			if qc.failedOnly && obs.Ok {
				return nil
			}
			match := strings.Contains
			if qc.exactMatch {
				match = func(s, t string) bool { return s == t }
			}
			if qc.src != "" && !match(obs.SrcHost, qc.src) {
				return nil
			}
			if qc.dest != "" && !match(obs.DestHost, qc.dest) {
				return nil
			}
			if qc.jobID != "" && !match(obs.JobID, qc.jobID) {
				return nil
			}
			if count == 0 {
				fmt.Printf("[")
			} else {
				fmt.Printf(",\n")
			}
			count++
			t := obs.Timestamp.AsTime().UTC().Format("2006-01-02T15:04:05.000Z")
			dur := ""
			if obs.Duration != nil {
				dur = fmt.Sprintf(`,"duration": "%dms"`, obs.Duration.AsDuration().Milliseconds())
			}
			fmt.Printf("{%q: %q, %q: %q, %q: %q, %q: %q%s, %q: %t}", "time", t, "src", obs.SrcHost, "dest", obs.DestHost, "jobID", obs.JobID, dur, "ok", obs.Ok)
			return nil
		}); err != nil {
			return err
		}
	}
	if count > 0 {
		fmt.Printf("]\n")
	} else {
		fmt.Printf("[]\n")
	}
	return nil
}
