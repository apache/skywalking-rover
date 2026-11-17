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
	"strings"

	"github.com/cilium/ebpf"
)

// The L2 to L4 details of the socket calls (access_log.kernel_metrics.l2_l3, bpf/accesslog/l24): the programs whose
// name starts with l24Prefix, the maps below and the load-time constant kernel_metrics_l2_l3.
//
// With the switch off the constant is 0, so the verifier drops every branch of the socket call programs on it, the
// l24 programs are loaded as stubs (not verified, never attached) and their maps are made with one entry: the object
// loads and runs as it did without them. With it on, an l24 program the kernel refuses is loaded as a stub as well
// (its hook is not attached, its metrics stay 0) instead of failing the load of the whole object.

const (
	l24Prefix   = "l24_"
	l24Variable = "kernel_metrics_l2_l3"
)

// l24Maps are the maps only the l24 programs use
var l24Maps = []string{"sk_buff_receive_detail_map", "sk_buff_transmit_detail_map", "sk_temp_args_map",
	"ip_list_rcv_args_map"}

// l24Plan is what the loader makes of the l24 programs
type l24Plan struct {
	enabled bool
	// stubbed are the l24 programs the kernel refused, loaded as stubs (enabled only)
	stubbed map[string]error
}

func newL24Plan(enabled bool) *l24Plan {
	return &l24Plan{enabled: enabled, stubbed: map[string]error{}}
}

// isL24Program tells whether the program is one of bpf/accesslog/l24
func isL24Program(name string) bool {
	return strings.HasPrefix(name, l24Prefix)
}

// setL24Constant sets kernel_metrics_l2_l3 of the object (a build without it has none to set)
func setL24Constant(spec *ebpf.CollectionSpec, enabled bool) error {
	v, ok := spec.Variables[l24Variable]
	if !ok {
		return nil
	}
	value := uint32(0)
	if enabled {
		value = 1
	}
	return v.Set(value)
}

// apply stubs the l24 programs that are not loaded and shrinks the maps of the switch off
func (p *l24Plan) apply(spec *ebpf.CollectionSpec) {
	for name, program := range spec.Programs {
		if !isL24Program(name) {
			continue
		}
		if _, refused := p.stubbed[name]; !p.enabled || refused {
			stubProgram(program)
		}
	}
	if !p.enabled {
		for _, name := range l24Maps {
			if m := spec.Maps[name]; m != nil {
				m.MaxEntries = 1
			}
		}
	}
}

// refused gives the l24 program the load error names, "" when the error is not one of an l24 program (or that program
// is already a stub)
func (p *l24Plan) refused(spec *ebpf.CollectionSpec, err error) string {
	if !p.enabled || err == nil {
		return ""
	}
	msg := err.Error()
	for name := range spec.Programs {
		if !isL24Program(name) {
			continue
		}
		if _, done := p.stubbed[name]; done {
			continue
		}
		if strings.Contains(msg, "program "+name+":") {
			return name
		}
	}
	return ""
}

// Loaded tells whether the l24 program is loaded for real (the switch is on and the kernel took it)
func (p *l24Plan) Loaded(name string) bool {
	if p == nil || !p.enabled {
		return false
	}
	_, refused := p.stubbed[name]
	return !refused
}

// KernelMetricsL2L3 tells whether the L2 to L4 details are on (access_log.kernel_metrics.l2_l3)
func (l *Loader) KernelMetricsL2L3() bool {
	return l.l24 != nil && l.l24.enabled
}

// L24ProgramLoaded tells whether the l24 program (its name in the object, l24_*) is loaded for real, see l24Plan
func (l *Loader) L24ProgramLoaded(name string) bool {
	return l.l24.Loaded(name)
}

// L24RefusedPrograms are the l24 programs the kernel refused with the errors, loaded as stubs
func (l *Loader) L24RefusedPrograms() map[string]error {
	if l.l24 == nil {
		return nil
	}
	return l.l24.stubbed
}
