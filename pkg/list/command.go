// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common"
	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/client-go/kubernetes"
)

type listCommand struct {
	kubeconfig string
	targetPort int
	since      time.Duration
	limit      int
	jobIDs     []string
	srcHosts   []string
	destHosts  []string
	failedOnly bool
	window     time.Duration

	clientset *kubernetes.Clientset
}

func CreateListCmd() *cobra.Command {
	lc := &listCommand{}
	cmd := &cobra.Command{
		Use:   "list (observation|obs|aggregated|aggr) <podname>",
		Short: "collect observations or aggregations from an agent",
		Long:  `collect observations from an agent using 'kubectl port-forward' and GRPC'`,
		RunE:  lc.list,
	}
	cmd.Flags().StringVar(&lc.kubeconfig, "kubeconfig", "", "kubeconfig for shoot cluster, uses KUBECONFIG if not specified.")
	cmd.Flags().IntVar(&lc.targetPort, "targetPort", 0, "target pod port")
	cmd.Flags().DurationVar(&lc.since, "since", 10*time.Minute, "list observations since given time period.")
	cmd.Flags().IntVar(&lc.limit, "limit", 10000, "maximum number of observations to retrieve.")
	cmd.Flags().StringArrayVar(&lc.jobIDs, "job", nil, "jobID(s) to filter")
	cmd.Flags().StringArrayVar(&lc.srcHosts, "src", nil, "sourc host(s) to filter")
	cmd.Flags().StringArrayVar(&lc.destHosts, "dest", nil, "destination host(s) to filter")
	cmd.Flags().BoolVar(&lc.failedOnly, "failed-only", false, "only failures")
	cmd.Flags().DurationVar(&lc.window, "window", 1*time.Minute, "aggregation window (only for aggregated observations)")
	return cmd
}

func (lc *listCommand) list(ccmd *cobra.Command, args []string) error {
	log := logrus.WithField("cmd", "list")

	if len(args) != 2 {
		return fmt.Errorf("Missing kind or pod name: %s", strings.Join(args, " "))
	}

	aggr := false
	switch args[0] {
	case "aggr":
		fallthrough
	case "aggregated":
		aggr = true
	case "obs":
		fallthrough
	case "observation":
		aggr = false
	default:
		return fmt.Errorf("Invalid kind: %s (allowed 'observation', 'obs', 'aggregated', 'aggr')", args[0])
	}

	podname := args[1]
	port := 18007
	for !lc.checkPortAvailable(port) {
		port++
	}
	targetPort := lc.targetPort
	if targetPort == 0 {
		if strings.HasPrefix(podname, common.NameDaemonSetAgentHostNet) {
			targetPort = common.HostNetPodGRPCPort
		} else {
			targetPort = common.PodNetPodGRPCPort
		}
	}

	kubeconfigOpt := ""
	if lc.kubeconfig != "" {
		kubeconfigOpt = " --kubeconfig=" + lc.kubeconfig
	}

	log.Infof("Loading observations from pod %s", podname)
	cmdline := fmt.Sprintf("kubectl %s -n kube-system  port-forward %s %d:%d", kubeconfigOpt, podname, port, targetPort)
	var stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} //create process group for child processes
	cmd.Stderr = &stderr
	cmd.Env = os.Environ()
	err := cmd.Start()
	if err != nil {
		return err
	}
	defer func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()

	cc, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), grpc.WithInsecure())
	if err != nil {
		return err
	}

	client := nwpd.NewAgentServiceClient(cc)
	request := &nwpd.GetObservationsRequest{
		Start:               timestamppb.New(time.Now().Add(-lc.since)),
		Limit:               int32(lc.limit),
		RestrictToJobIDs:    lc.jobIDs,
		RestrictToSrcHosts:  lc.srcHosts,
		RestrictToDestHosts: lc.destHosts,
		FailuresOnly:        lc.failedOnly,
		AggregationWindow:   durationpb.New(lc.window),
	}

	for i := 0; i < 20; i++ {
		if !lc.checkPortAvailable(port) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if aggr {
		return lc.listAggregatedObservations(log, client, request)
	} else {
		return lc.listObservations(log, client, request)
	}
}

func (cc *listCommand) listObservations(log logrus.FieldLogger, client nwpd.AgentServiceClient, request *nwpd.GetObservationsRequest) error {
	ctx := context.Background()
	response, err := client.GetObservations(ctx, request)
	if err != nil {
		return err
	}
	for _, obs := range response.Observations {
		dur := ""
		if obs.Duration != nil {
			dur = fmt.Sprintf(" duration=%dms", obs.Duration.AsDuration().Milliseconds())
		}
		status := "ok"
		if !obs.Ok {
			status = "failed"
		}
		fmt.Printf("%s src=%s dest=%s jobid=%s%s status=%s\n", obs.Timestamp.AsTime().UTC().Format("2006-01-02T15:04:05.000Z"),
			obs.SrcHost, obs.DestHost, obs.JobID, dur, status)
	}
	log.Infof("%d observations", len(response.Observations))

	return nil
}

func (cc *listCommand) listAggregatedObservations(log logrus.FieldLogger, client nwpd.AgentServiceClient, request *nwpd.GetObservationsRequest) error {
	ctx := context.Background()
	response, err := client.GetAggregatedObservations(ctx, request)
	if err != nil {
		return err
	}
	for _, ao := range response.AggregatedObservations {
		jobIDs := map[string]struct{}{}
		for k := range ao.JobsOkCount {
			jobIDs[k] = struct{}{}
		}
		for k := range ao.JobsNotOkCount {
			jobIDs[k] = struct{}{}
		}
		for jobID := range jobIDs {
			okCount := ao.JobsOkCount[jobID]
			notOkCount := ao.JobsNotOkCount[jobID]
			dur := ""
			if ao.MeanOkDuration[jobID] != nil {
				dur = fmt.Sprintf(" meanDuration=%dms", ao.MeanOkDuration[jobID].AsDuration().Milliseconds())
			}
			window := ao.PeriodEnd.AsTime().Sub(ao.PeriodStart.AsTime())
			fmt.Printf("%s %s src=%s dest=%s jobid=%s%s ok=%d failures=%d\n", ao.PeriodStart.AsTime().UTC().Format("2006-01-02T15:04:05.000Z"),
				window, ao.SrcHost, ao.DestHost, jobID, dur, okCount, notOkCount)
		}
	}
	log.Infof("%d aggregated observations", len(response.AggregatedObservations))

	return nil
}

func (cc *listCommand) checkPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
