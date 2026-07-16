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

package host

import "testing"

// TestGetHostSysInHost guards the prefix the cgroup tree is read through.
//
// This matters more than it looks: if the mapping were ignored and /sys used directly, the agent
// would read its *own* cgroup subtree, where none of the node's containers are. Nothing would
// error - the walk would just map no containers, and every cgroup lookup would miss - so the
// symptom would be "no short-lived process is ever reported", which is indistinguishable from
// there being no traffic.
func TestGetHostSysInHost(t *testing.T) {
	original := hostSysMappingPath
	defer func() { hostSysMappingPath = original }()

	tests := []struct {
		name    string
		mapping string
		want    string
	}{
		{"unmapped, the real host path", "", "/sys/fs/cgroup"},
		{"mapped by the deployment", "/host/sys", "/host/sys/fs/cgroup"},
		{"mapping with a trailing slash", "/host/sys/", "/host/sys/fs/cgroup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostSysMappingPath = tt.mapping
			if got := GetHostSysInHost("fs/cgroup"); got != tt.want {
				t.Fatalf("GetHostSysInHost = %s, want %s", got, tt.want)
			}
		})
	}
}
