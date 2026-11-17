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

package analyze

import (
	"os"
	"runtime/debug"
	"testing"
)

// testMemoryLimit is the soft memory limit of the tests of this package. Several of them replay scripted traffic
// many times over and allocate in bursts: with the default pacing alone the heap grows to about 20GB in a run of the
// package, while what is live at once stays below 3GB, so the CI runner killed the process. The limit makes the
// collector keep up; GOMEMLIMIT, when set, wins.
const testMemoryLimit = 4 << 30

func TestMain(m *testing.M) {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(testMemoryLimit)
	}
	os.Exit(m.Run())
}
