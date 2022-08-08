/*
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package common

import (
	"sort"
	"time"
)

type StringSet map[string]struct{}

func (s StringSet) Add(key string) {
	s[key] = struct{}{}
}

func (s StringSet) AddAll(keys ...string) {
	for _, k := range keys {
		s[k] = struct{}{}
	}
}

func (s StringSet) Contains(key string) bool {
	_, ok := s[key]
	return ok
}

func (s StringSet) Delete(key string) {
	delete(s, key)
}

func (s StringSet) Len() int {
	return len(s)
}

func (s StringSet) ToSortedArray() []string {
	list := make([]string, 0, len(s))
	for key := range s {
		list = append(list, key)
	}
	sort.Strings(list)
	return list
}

func FormatAsUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
