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
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

const (
	// AutoParallels sizes the analyze parallels from the CPUs the process may use
	AutoParallels = "auto"

	minAutoParallels = 2
	maxAutoParallels = 10
)

// Parallels is a count of parallel analyzers: a positive integer, or "auto" (or 0) to size it from
// GOMAXPROCS. It is a string so the config accepts both a YAML integer and a string from the environment.
type Parallels string

// Resolve the count of parallels, using gomaxprocs for "auto"
func (p Parallels) Resolve(gomaxprocs int) (int, error) {
	value := strings.TrimSpace(string(p))
	if value == "" || strings.EqualFold(value, AutoParallels) {
		return AutoParallelCount(gomaxprocs), nil
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return 0, fmt.Errorf("the parallels must be a positive integer or %q, but is %q", AutoParallels, value)
	}
	if count == 0 {
		return AutoParallelCount(gomaxprocs), nil
	}
	return count, nil
}

// AutoParallelCount is 2 x gomaxprocs, bounded to [2, 10]. GOMAXPROCS follows the CPU limit of the
// container, so 1.5 cores give 4 partitions and 5 or more cores give 10.
func AutoParallelCount(gomaxprocs int) int {
	count := 2 * gomaxprocs
	if count < minAutoParallels {
		return minAutoParallels
	}
	if count > maxAutoParallels {
		return maxAutoParallels
	}
	return count
}

// ResolveAnalyzeParallels resolves the analyze parallels of the connection and protocol analyze once
// at startup and logs them, the analyzers then read AnalyzeParallelCount.
func (c *Config) ResolveAnalyzeParallels() error {
	gomaxprocs := runtime.GOMAXPROCS(0)
	connection, err := c.ConnectionAnalyze.AnalyzeParallels.Resolve(gomaxprocs)
	if err != nil {
		return fmt.Errorf("access_log.connection_analyze.analyze_parallels: %v", err)
	}
	protocol, err := c.ProtocolAnalyze.AnalyzeParallels.Resolve(gomaxprocs)
	if err != nil {
		return fmt.Errorf("access_log.protocol_analyze.analyze_parallels: %v", err)
	}
	c.ConnectionAnalyze.analyzeParallels = connection
	c.ProtocolAnalyze.analyzeParallels = protocol
	log.Infof("access log analyze parallels: connection %d (configured %q), protocol %d (configured %q), GOMAXPROCS %d",
		connection, string(c.ConnectionAnalyze.AnalyzeParallels), protocol, string(c.ProtocolAnalyze.AnalyzeParallels), gomaxprocs)
	return nil
}

// AnalyzeParallelCount is the resolved count of connection analyzers, 0 before ResolveAnalyzeParallels
func (c *ConnectionAnalyzeConfig) AnalyzeParallelCount() int {
	return c.analyzeParallels
}

// AnalyzeParallelCount is the resolved count of protocol analyzers, 0 before ResolveAnalyzeParallels
func (c *ProtocolAnalyzeConfig) AnalyzeParallelCount() int {
	return c.analyzeParallels
}
