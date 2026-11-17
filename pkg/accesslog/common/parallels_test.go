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

package common //nolint:revive // package name is acceptable in this context

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apache/skywalking-rover/pkg/config"
)

func TestParallelsResolve(t *testing.T) {
	cases := []struct {
		value      Parallels
		gomaxprocs int
		want       int
		wantErr    bool
	}{
		{value: "3", gomaxprocs: 8, want: 3},
		{value: " 12 ", gomaxprocs: 1, want: 12},
		{value: "auto", gomaxprocs: 1, want: 2},
		{value: "AUTO", gomaxprocs: 2, want: 4},
		{value: "0", gomaxprocs: 2, want: 4},
		{value: "", gomaxprocs: 16, want: 10},
		{value: "-1", gomaxprocs: 4, wantErr: true},
		{value: "1.5", gomaxprocs: 4, wantErr: true},
		{value: "many", gomaxprocs: 4, wantErr: true},
	}
	for _, c := range cases {
		got, err := c.value.Resolve(c.gomaxprocs)
		if c.wantErr {
			if err == nil {
				t.Errorf("Resolve(%q) = %d, want an error", c.value, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Resolve(%q, %d) = %d, %v, want %d", c.value, c.gomaxprocs, got, err, c.want)
		}
	}
}

func TestAutoParallelCount(t *testing.T) {
	for gomaxprocs, want := range map[int]int{0: 2, 1: 2, 2: 4, 3: 6, 4: 8, 5: 10, 8: 10, 64: 10} {
		if got := AutoParallelCount(gomaxprocs); got != want {
			t.Errorf("AutoParallelCount(%d) = %d, want %d", gomaxprocs, got, want)
		}
	}
}

// the config loader must accept a YAML integer, a YAML string and an environment value
func TestAnalyzeParallelsDecode(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	content := `access_log:
  connection_analyze:
    analyze_parallels: 3
  protocol_analyze:
    analyze_parallels: ${TEST_ROVER_PROTOCOL_ANALYZE_PARALLELS:auto}
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  string
		want Parallels
	}{{env: "", want: "auto"}, {env: "7", want: "7"}} {
		t.Setenv("TEST_ROVER_PROTOCOL_ANALYZE_PARALLELS", c.env)
		conf, err := config.Load(file)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &Config{}
		if err := conf.UnMarshalWithKey("access_log", cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.ConnectionAnalyze.AnalyzeParallels != "3" || cfg.ProtocolAnalyze.AnalyzeParallels != c.want {
			t.Fatalf("decoded %q/%q, want 3/%q", cfg.ConnectionAnalyze.AnalyzeParallels, cfg.ProtocolAnalyze.AnalyzeParallels, c.want)
		}
		if err := cfg.ResolveAnalyzeParallels(); err != nil {
			t.Fatal(err)
		}
		if cfg.ConnectionAnalyze.AnalyzeParallelCount() != 3 || cfg.ProtocolAnalyze.AnalyzeParallelCount() < 2 {
			t.Fatalf("resolved %d/%d", cfg.ConnectionAnalyze.AnalyzeParallelCount(), cfg.ProtocolAnalyze.AnalyzeParallelCount())
		}
	}

	cfg := &Config{ProtocolAnalyze: ProtocolAnalyzeConfig{AnalyzeParallels: "x"}}
	if err := cfg.ResolveAnalyzeParallels(); err == nil {
		t.Fatal("an invalid value must fail the resolution")
	}
}
