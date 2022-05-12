// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"encoding/binary"
	"fmt"
	"sync"
)

type IntString struct {
	key   int64
	value string
}

func NewVarint2String(key int64, value string) *IntString {
	return &IntString{
		key:   key,
		value: value,
	}
}

func NewVarint2StringFromBytes(key []byte, value []byte) *IntString {
	k, _ := binary.Varint(key)
	return &IntString{
		key:   k,
		value: string(value),
	}
}

func Int64Bytes(value int64) []byte {
	out := make([]byte, 8)
	n := binary.PutVarint(out, value)
	return out[:n]
}

func (x *IntString) KeyBytes() []byte {
	return Int64Bytes(x.key)
}

func (x *IntString) ValueBytes() []byte {
	return []byte(x.value)
}

func (x *IntString) Key() int64 {
	return x.key
}

func (x *IntString) Value() string {
	return x.value
}

type IntStringPersistor interface {
	Persist(obj *IntString) error
}

type StringIdMap struct {
	lock   sync.Mutex
	str2id map[string]int64
	id2str map[int64]string
	last   int64
}

func NewStringIdMap() *StringIdMap {
	return NewStringIdMapFromData(nil)
}

func NewStringIdMapFromData(data []*IntString) *StringIdMap {
	m := &StringIdMap{
		str2id: map[string]int64{},
		id2str: map[int64]string{},
	}
	if len(data) > 0 {
		for _, item := range data {
			m.str2id[item.value] = item.key
			m.id2str[item.key] = item.value
			if item.key >= m.last {
				m.last = item.key
			}
		}
	}
	return m
}

func (m *StringIdMap) Append(item *IntString) error {
	if item.key != m.last+1 {
		return fmt.Errorf("invalid add: %d != %d", item.key, m.last+1)
	}

	m.str2id[item.value] = item.key
	m.id2str[item.key] = item.value
	m.last = item.key
	return nil
}

func (m *StringIdMap) GetKey(persistor IntStringPersistor, s string) (int64, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if s == "" {
		return 0, nil
	}
	key := m.str2id[s]
	if key == 0 {
		m.last++
		key = m.last
		if persistor != nil {
			err := persistor.Persist(&IntString{
				key:   key,
				value: s,
			})
			if err != nil {
				return 0, err
			}
		}
		m.str2id[s] = key
		m.id2str[key] = s
	}
	return key, nil
}

func (m *StringIdMap) GetValue(id int64) (string, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if id == 0 {
		return "", nil
	}
	s := m.id2str[id]
	if s == "" {
		return "", fmt.Errorf("%d not found", id)
	}
	return s, nil
}
