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

package bpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestEveryProgramLoads loads every program of the access log object into the kernel on its own. The
// socket data upload is unrolled into each syscall exit and TLS uretprobe, so a change to the upload
// chunk count or to the chunk body can push those programs over the verifier's 1M processed
// instruction limit ("BPF program is too large"), which no unit test of the Go side would notice and
// which makes the whole access log module fail to start. Needs root, skipped otherwise.
func TestEveryProgramLoads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise the memlock limit: %v", err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("cannot read the access log BPF object: %v", err)
	}
	for name, program := range spec.Programs {
		single := &ebpf.CollectionSpec{
			Maps:      spec.Maps,
			Programs:  map[string]*ebpf.ProgramSpec{name: program},
			Types:     spec.Types,
			ByteOrder: spec.ByteOrder,
		}
		collection, err := ebpf.NewCollection(single)
		if err != nil {
			t.Errorf("program %s cannot be loaded: %v", name, err)
			continue
		}
		collection.Close()
	}
}
