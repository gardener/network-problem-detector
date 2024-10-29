// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"

	"github.com/gardener/network-problem-detector/pkg/agent/db"
	"github.com/gardener/network-problem-detector/pkg/common"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.uber.org/atomic"
	"golang.org/x/sync/semaphore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type collectCommand struct {
	common.ClientsetBase
	directory string
	workers   int

	totalBytes  atomic.Int64
	totalFiles  atomic.Int32
	totalNodes  atomic.Int32
	failedNodes atomic.Int32
}

func CreateCollectCmd() *cobra.Command {
	cc := &collectCommand{}
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "collect observations from all nodes",
		Long:  `collect observations generated by both node and pod daemonsets using 'kubectl exec' and 'tar'`,
		RunE:  cc.collect,
	}
	cc.AddKubeConfigFlag(cmd.Flags())
	cmd.Flags().StringVar(&cc.directory, "output", "collected-observations", "database directory to store the collected observations.")
	cmd.Flags().IntVar(&cc.workers, "workers", 10, "number of parallel workers to fetch observations")
	return cmd
}

func (cc *collectCommand) collect(_ *cobra.Command, _ []string) error {
	log := logrus.WithField("cmd", "collect")

	if err := os.MkdirAll(cc.directory, 0o750); err != nil { //  #nosec G302 -- no sensitive data
		return err
	}

	if err := cc.SetupClientSet(); err != nil {
		return err
	}

	ctx := context.Background()
	list, err := cc.Clientset.CoreV1().Pods(common.NamespaceKubeSystem).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", common.LabelKeyK8sApp, common.NameDaemonSetAgentHostNet),
	})
	if err != nil {
		return fmt.Errorf("listing pods failed: %w", err)
	}

	dir, err := os.MkdirTemp("", "nwpd-collect-")
	if err != nil {
		return fmt.Errorf("creating temporary directory failed: %w", err)
	}
	defer os.RemoveAll(dir)

	log.Infof("Collecting from %d nodes...", len(list.Items))
	cc.totalBytes.Store(0)
	cc.totalFiles.Store(0)
	cc.totalNodes.Store(0)
	cc.failedNodes.Store(0)
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(int64(cc.workers))
	wg.Add(len(list.Items))
	for _, item := range list.Items {
		pod := item
		go func() {
			defer wg.Done()
			tasklog := log.WithField("node", pod.Spec.NodeName)
			if err := sem.Acquire(ctx, 1); err != nil {
				tasklog.Errorf("acquire failed")
				return
			}
			defer sem.Release(1)
			cc.loadFrom(tasklog, filepath.Join(dir, pod.Name), &pod)
		}()
	}
	wg.Wait()
	log.Infof("Written %d bytes form %d files to directory %s from %d nodes",
		cc.totalBytes.Load(), cc.totalFiles.Load(), cc.directory, cc.totalNodes.Load())
	if cc.failedNodes.Load() > 0 {
		log.Warnf("%d nodes not completed (see log messages above)", cc.failedNodes.Load())
	}

	return nil
}

func (cc *collectCommand) loadFrom(log logrus.FieldLogger, dir string, pod *corev1.Pod) {
	log.Infof("Loading observations")
	kubeconfigOpt := ""
	if cc.Kubeconfig != "" {
		kubeconfigOpt = " --kubeconfig=" + cc.Kubeconfig
	}
	if err := os.Mkdir(dir, 0o750); err != nil { //  #nosec G302 -- no sensitive data
		log.Errorf("mkdir tmpsubdir failed: %s", err)
		cc.failedNodes.Inc()
		return
	}
	cmdline := fmt.Sprintf("kubectl %s -n %s exec %s -- /nwpdcli run-collect | tar xfz - -C %s", kubeconfigOpt, pod.Namespace, pod.Name, dir)
	var stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", cmdline) //  #nosec G204 -- only used in interactive shell
	cmd.Stderr = &stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err != nil {
		log.Errorf("kubectl exec failed for %s/%s: %s (stderr: %s)", pod.Namespace, pod.Name, err, stderr.String())
		cc.failedNodes.Inc()
		return
	}
	filenames, err := db.GetAnyRecordFiles(dir, false)
	if err != nil {
		log.Errorf("listing temp dir %s failed: %s", dir, err)
		cc.failedNodes.Inc()
		return
	}
	if len(filenames) == 0 && stderr.Len() != 0 {
		log.Errorf("execution with unexpected result: %s", stderr.String())
		cc.failedNodes.Inc()
		return
	}

	outdir := path.Join(cc.directory, pod.Spec.NodeName)
	if err := os.MkdirAll(outdir, 0o750); err != nil { //  #nosec G302 -- no sensitive data
		log.Errorf("mkdir failed: %s", err)
		cc.failedNodes.Inc()
		return
	}
	countBytes := 0
	countFiles := 0
	for _, filename := range filenames {
		_, name := path.Split(filename)
		destFilename := path.Join(outdir, name)
		n, err := copyFile(filename, destFilename)
		if err != nil {
			log.Errorf("copyFile failed: %s", err)
			cc.failedNodes.Inc()
			return
		}
		err = copyFileDates(filename, destFilename)
		if err != nil {
			log.Errorf("copyFileDates failed: %s", err)
			cc.failedNodes.Inc()
			return
		}
		countBytes += int(n)
		countFiles++
	}
	log.Infof("Loaded %d bytes from %d files", countBytes, countFiles)
	cc.totalBytes.Add(int64(countBytes))
	cc.totalFiles.Add(int32(countFiles))
	cc.totalNodes.Inc()
}

func copyFile(srcFilename, destFilename string) (int64, error) {
	input, err := os.Open(filepath.Clean(srcFilename))
	if err != nil {
		return 0, err
	}
	defer input.Close()

	output, err := os.Create(filepath.Clean(destFilename))
	if err != nil {
		return 0, err
	}
	defer output.Close()

	return io.Copy(output, input)
}

func copyFileDates(srcFilename, destFilename string) error {
	stat, err := os.Stat(srcFilename)
	if err != nil {
		return err
	}
	return os.Chtimes(destFilename, stat.ModTime(), stat.ModTime())
}
