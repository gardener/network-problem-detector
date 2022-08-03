// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gardener/network-problem-detector/pkg/common/nwpd"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type obsWriter struct {
	log            logrus.FieldLogger
	directory      string
	prefix         string
	retentionHours int
	currentFile    atomic.Value
	obsChan        chan *nwpd.Observation
	done           chan struct{}
	ticker         *time.Ticker
}

const (
	markerStringID    = 1
	markerObservation = 2
	markerOpen        = 127
)

type writeFile struct {
	filename string
	end      time.Time
	file     *os.File
	idMap    *StringIdMap
}

var _ IntStringPersistor = &writeFile{}

func (wf *writeFile) Persist(obj *IntString) error {
	raw := &nwpd.IntString{
		Key:   obj.Key(),
		Value: obj.Value(),
	}
	bytes, err := proto.Marshal(raw)
	if err != nil {
		return err
	}
	return writeRecord(wf.file, markerStringID, bytes)
}

var _ nwpd.ObservationWriter = &obsWriter{}

func NewObsWriter(log logrus.FieldLogger, directory, prefix string, retentionHours int) (*obsWriter, error) {
	err := os.MkdirAll(directory, 0777)
	if err != nil {
		return nil, err
	}
	writer := &obsWriter{
		log:            log,
		directory:      directory,
		prefix:         prefix,
		retentionHours: retentionHours,
		obsChan:        make(chan *nwpd.Observation, 100),
		done:           make(chan struct{}),
		ticker:         time.NewTicker(5 * time.Second),
	}

	return writer, nil
}

func (w *obsWriter) Add(obs *nwpd.Observation) {
	w.obsChan <- obs
}

func (w *obsWriter) Stop() {
	if w.ticker != nil {
		w.ticker.Stop()
		w.ticker = nil
	}
	w.done <- struct{}{}
	file := w.currentFile.Load().(*writeFile)
	if file != nil {
		_ = file.file.Close()
	}
}

func (w *obsWriter) Run() {
	for {
		select {
		case <-w.done:
			return
		case <-w.ticker.C:
			file, err := w.getFile()
			if err != nil {
				w.log.Warnf("sync failed: getFile: %s", err)
				continue
			}
			err = file.file.Sync()
			if err != nil {
				w.log.Warnf("sync failed: %s", err)
				continue
			}
		case obs := <-w.obsChan:
			file, err := w.getFile()
			if err != nil {
				w.log.Warnf("write failed: getFile: %s", err)
				continue
			}
			intobs, err := ToIntObservation(obs, file.idMap, file)
			if err != nil {
				w.log.Warnf("write failed: ToIntObservation: %s", err)
				continue
			}
			value, err := IntObsToBytes(intobs)
			if err != nil {
				w.log.Warnf("write failed: IntObsToBytes: %s", err)
				continue
			}
			if err := writeRecord(file.file, markerObservation, value); err != nil {
				w.log.Warnf("write failed: %s", err)
				continue
			}
		}
	}
}

func writeRecord(w io.Writer, marker byte, value []byte) error {
	if _, err := w.Write([]byte{marker}); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint16(len(value))); err != nil {
		return err
	}

	if _, err := w.Write(value); err != nil {
		return err
	}
	return nil
}

func readRecord(r io.Reader) (byte, []byte, error) {
	marker := make([]byte, 1)
	if n, err := r.Read(marker); err == io.EOF {
		return 0, nil, nil
	} else if err != nil {
		return 0, nil, err
	} else if n != 1 {
		return 0, nil, fmt.Errorf("missing marker")
	}

	var len uint16
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return 0, nil, err
	}
	value := make([]byte, len)
	if n, err := r.Read(value); err != nil {
		return 0, nil, err
	} else if n != int(len) {
		return 0, nil, fmt.Errorf("incomplete block: %d != %d", n, int(len))
	}
	return marker[0], value, nil
}

func (w *obsWriter) loadStringIdMap(filename string) (*StringIdMap, error) {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		if os.IsNotExist(err) {
			return NewStringIdMap(), nil
		}
		return nil, err
	}

	var objects []*IntString
	for {
		marker, value, err := readRecord(f)
		if err != nil {
			return nil, fmt.Errorf("reading StringIdMap failed: %s", err)
		}
		if value == nil {
			break
		}
		switch marker {
		case markerStringID:
			raw := &nwpd.IntString{}
			if err := proto.Unmarshal(value, raw); err != nil {
				return nil, fmt.Errorf("reading StringIdMap from file %s failed: %s", filename, err)
			}
			obj := NewVarint2String(raw.Key, raw.Value)
			objects = append(objects, obj)
		case markerObservation:
			// ignore
		case markerOpen:
			// ignore
		default:
			return nil, fmt.Errorf("invalid file format")
		}
	}
	idMap := NewStringIdMapFromData(objects)
	return idMap, nil
}

func (w *obsWriter) getFile() (*writeFile, error) {
	now := time.Now().UTC()
	var file *writeFile
	if f, ok := w.currentFile.Load().(*writeFile); ok {
		file = f
	}
	if file == nil || now.After(file.end) {
		go func() {
			w.cleanOldFiles()
		}()
		// rotate output file
		if file != nil {
			if err := file.file.Close(); err != nil {
				w.log.Warnf("closing file %s failed: %s", file.filename, err)
			}
		}
		currentUTC := startOfHourUTC(now)
		next := now.Add(61 * time.Minute)
		nextUTC := startOfHourUTC(next)
		filename := fmt.Sprintf("%s/%s-%s.records", w.directory, w.prefix, currentUTC.Format("2006-01-02-15"))
		idMap, err := w.loadStringIdMap(filename)
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		err = writeRecord(f, markerOpen, []byte(now.UTC().Format("15:04:05")))
		if err != nil {
			return nil, err
		}
		file = &writeFile{
			filename: filename,
			end:      nextUTC,
			idMap:    idMap,
			file:     f,
		}
		w.currentFile.Store(file)
	}
	return file, nil
}

func (w *obsWriter) sync() {
	if f, ok := w.currentFile.Load().(*writeFile); ok {
		_ = f.file.Sync()
	}
}

func (w *obsWriter) cleanOldFiles() {
	hours := w.retentionHours
	if hours <= 0 {
		hours = 1
	}
	limit := time.Now().Add(-time.Duration(hours) * time.Hour)
	limitUTC := startOfHourUTC(limit)
	files, err := ioutil.ReadDir(w.directory)
	if err != nil {
		w.log.Warnf("cannot read directory %s: %s", w.directory, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), w.prefix) && f.ModTime().Before(limitUTC) {
			filename := path.Join(w.directory, f.Name())
			if err := os.Remove(filename); err != nil {
				w.log.Warnf("cannot delete file %s: %s", filename, err)
			} else {
				w.log.Infof("deleted file %s", filename)
			}
		}
	}
}

type filterFunc func(key string) bool

func all(_ string) bool { return true }

func createFilter(keys []string) filterFunc {
	if keys == nil {
		return all
	}
	m := map[string]struct{}{}
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return func(key string) bool {
		_, ok := m[key]
		return ok
	}
}

func (w *obsWriter) ListObservations(options nwpd.ListObservationsOptions) (nwpd.Observations, error) {
	var result nwpd.Observations

	var empty time.Time
	now := time.Now()
	startLimit := now.Add(-24 * time.Hour)
	start := options.Start
	if start.After(now) {
		start = now
	} else if start.Before(startLimit) {
		start = startLimit
	}
	end := options.End
	if end == empty {
		end = now
	} else if end.After(start) || end.Before(startLimit) {
		return nil, nil
	}

	limit := options.Limit
	if limit == 0 {
		limit = 10000
	}
	jobIDFilter := createFilter(options.FilterJobIDs)
	srcHostFilter := createFilter(options.FilterSrcHosts)
	descHostFilter := createFilter(options.FilterDestHosts)

	files, err := GetRecordFiles(w.directory, w.prefix, start, end)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if len(result) == limit {
			break
		}
		err := IterateRecordFile(file, func(obs *nwpd.Observation) error {
			if len(result) == limit {
				return nil
			}
			if t := obs.Timestamp.AsTime(); t.Before(start) || t.After(end) {
				return nil
			}
			if obs.Ok && options.FailuresOnly {
				return nil
			}
			if !jobIDFilter(obs.JobID) || !srcHostFilter(obs.SrcHost) || !descHostFilter(obs.DestHost) {
				return nil
			}
			result = append(result, obs)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Sort(result)
	return result, nil
}

func startOfHourUTC(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
}

// GetRecordFiles gets all observation record files
func GetRecordFiles(directory, prefix string, start, end time.Time) ([]string, error) {
	startHour := startOfHourUTC(start)
	endHour := startOfHourUTC(end)
	var files []string
	for hour := startHour; !hour.After(endHour); hour = hour.Add(time.Hour) {
		filename := fmt.Sprintf("%s/%s-%s.records", directory, prefix, hour.Format("2006-01-02-15"))
		if stat, err := os.Stat(filename); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		} else {
			if stat.IsDir() {
				return nil, fmt.Errorf("%s is not a file", filename)
			}
			files = append(files, filename)
		}
	}
	return files, nil
}

// GetAnyRecordFiles gets all observation record files
func GetAnyRecordFiles(directory string, subdir bool) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			if subdir {
				subfiles, err := GetAnyRecordFiles(path.Join(directory, entry.Name()), false)
				if err != nil {
					return nil, err
				}
				files = append(files, subfiles...)
			}
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".records") {
			continue
		}
		files = append(files, path.Join(directory, entry.Name()))
	}
	return files, nil
}

type ObservationVisitor func(obs *nwpd.Observation) error

func IterateRecordFile(filename string, visitor ObservationVisitor) error {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}

	idMap := NewStringIdMap()
	for {
		marker, value, err := readRecord(f)
		if err != nil {
			return err
		}
		if value == nil {
			break
		}
		switch marker {
		case markerStringID:
			raw := &nwpd.IntString{}
			if err := proto.Unmarshal(value, raw); err != nil {
				return fmt.Errorf("error on reading StringIdMap: %s", err)
			}
			obj := NewVarint2String(raw.Key, raw.Value)
			if err := idMap.Append(obj); err != nil {
				return fmt.Errorf("error on appending to StringIdMap: %s", err)
			}
		case markerObservation:
			intobs, err := IntObsFromBytes(value)
			if err != nil {
				return fmt.Errorf("error on unmarshalling: %s", err)
			}
			obs, err := IntObsToObservation(intobs, idMap)
			if err != nil {
				return fmt.Errorf("error on converting observation: %s", err)
			}
			if err := visitor(obs); err != nil {
				return err
			}
		case markerOpen:
			// ignore
		default:
			return fmt.Errorf("invalid file format")
		}
	}
	return nil
}
