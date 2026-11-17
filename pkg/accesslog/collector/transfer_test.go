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

package collector

import (
	"testing"

	"github.com/apache/skywalking-rover/pkg/accesslog/common"
)

// TestValidateProtocolAnalyze: a per-CPU buffer that does not parse or is below a page, and a parallels or queue
// size below 1 are refused, as the analyze queue refused them before
func TestValidateProtocolAnalyze(t *testing.T) {
	valid := func() *common.Config {
		c := &common.Config{}
		c.ProtocolAnalyze.PerCPUBufferSize = "400KB"
		c.ProtocolAnalyze.ParseParallels = 1
		c.ProtocolAnalyze.QueueSize = 5000
		c.ProtocolAnalyze.AnalyzeParallels = "2"
		return c
	}
	cases := map[string]func(c *common.Config){
		"valid":                  func(*common.Config) {},
		"per_cpu_buffer garbage": func(c *common.Config) { c.ProtocolAnalyze.PerCPUBufferSize = "lots" },
		"per_cpu_buffer small":   func(c *common.Config) { c.ProtocolAnalyze.PerCPUBufferSize = "1KB" },
		"parse_parallels 0":      func(c *common.Config) { c.ProtocolAnalyze.ParseParallels = 0 },
		"queue_size 0":           func(c *common.Config) { c.ProtocolAnalyze.QueueSize = 0 },
	}
	for name, change := range cases {
		c := valid()
		change(c)
		if err := c.ResolveAnalyzeParallels(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		size, err := validateProtocolAnalyze(&c.ProtocolAnalyze)
		if (name == "valid") != (err == nil) {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "valid" && size != 400*1024 {
			t.Fatalf("per-CPU buffer %d", size)
		}
	}
	// not resolved: no analyzer
	c := valid()
	if _, err := validateProtocolAnalyze(&c.ProtocolAnalyze); err == nil {
		t.Fatal("analyze parallels not resolved")
	}
}
