// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package http1skip

import (
	"sync"
	"sync/atomic"
)

// ConnSync is what the analyzer of a connection tells the tracker: which events it received and when it
// held none of them, between messages. The analyzer registers it when it starts analyzing the HTTP/1 data
// of a connection and removes it with the connection.
type ConnSync struct {
	// appended is the decode sequence of the last event appended to the connection buffer
	appended atomic.Uint64
	// clean is the decode sequence up to which the analyzer received every event and then held no data
	// and no message in progress
	clean atomic.Uint64
}

// NoteAppended records an event appended to the connection buffer, after it was appended
func (s *ConnSync) NoteAppended(seq uint64) {
	if seq > s.appended.Load() {
		s.appended.Store(seq)
	}
}

// Appended is the decode sequence of the last event appended to the connection buffer. A caller that
// finds the buffer empty after loading it knows every event up to it was read.
func (s *ConnSync) Appended() uint64 {
	return s.appended.Load()
}

// MarkClean records that the analyzer received every event up to seq, holds none of them and is between
// messages
func (s *ConnSync) MarkClean(seq uint64) {
	if seq > s.clean.Load() {
		s.clean.Store(seq)
	}
}

type connKey struct {
	id, random uint64
}

// registry holds the ConnSync of every connection the analyzer has HTTP/1 state for
var registry sync.Map

// Register returns the ConnSync of a connection the analyzer starts analyzing
func Register(connectionID, randomID uint64) *ConnSync {
	s := &ConnSync{}
	registry.Store(connKey{id: connectionID, random: randomID}, s)
	return s
}

// Unregister removes the ConnSync of a connection the analyzer forgets
func Unregister(connectionID, randomID uint64, s *ConnSync) {
	registry.CompareAndDelete(connKey{id: connectionID, random: randomID}, s)
}

func lookup(k connKey) *ConnSync {
	if v, ok := registry.Load(k); ok {
		return v.(*ConnSync)
	}
	return nil
}

// ResetRegistry forgets every connection, for tests that run the same connections twice
func ResetRegistry() {
	registry.Range(func(k, _ any) bool {
		registry.Delete(k)
		return true
	})
}
