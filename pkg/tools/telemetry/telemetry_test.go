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

package telemetry

import (
	"strings"
	"testing"
)

func TestWriteRendersTheExpositionFormat(t *testing.T) {
	Register("test_events_in_use", "events held", Gauge, func() float64 { return 42 })
	RegisterSeries("test_pending", "pending per partition", Gauge, func() []Sample {
		return []Sample{
			{Labels: map[string]string{"partition": "1"}, Value: 7},
			{Labels: map[string]string{"partition": "0"}, Value: 3.5},
		}
	})
	var out strings.Builder
	if err := Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, want := range []string{
		"# HELP test_events_in_use events held",
		"# TYPE test_events_in_use gauge",
		"test_events_in_use 42",
		`test_pending{partition="1"} 7`,
		`test_pending{partition="0"} 3.5`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	// the metrics must be sorted by name so a diff of two scrapes is readable
	if strings.Index(out.String(), "test_events_in_use") > strings.Index(out.String(), "test_pending") {
		t.Error("metrics are not sorted by name")
	}
}

func TestRegisterReplacesTheReader(t *testing.T) {
	Register("test_replaced", "first", Gauge, func() float64 { return 1 })
	Register("test_replaced", "second", Gauge, func() float64 { return 2 })
	var out strings.Builder
	if err := Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Count(out.String(), "# HELP test_replaced") != 1 || !strings.Contains(out.String(), "test_replaced 2") {
		t.Errorf("a second registration must replace the first:\n%s", out.String())
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	RegisterSeries("test_escape", "escaping", Gauge, func() []Sample {
		return []Sample{{Labels: map[string]string{"name": `a"b\c`}, Value: 1}}
	})
	var out strings.Builder
	if err := Write(&out); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(out.String(), `test_escape{name="a\"b\\c"} 1`) {
		t.Errorf("label value not escaped:\n%s", out.String())
	}
}
