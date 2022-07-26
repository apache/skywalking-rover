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

import (
	"os"
	"strings"
)

var hostMappingPath string

func init() {
	hostMappingPath = os.Getenv("ROVER_HOST_MAPPING")
	// adapt with gopsutil framework to read the right process directory of host
	if hostMappingPath != "" {
		os.Setenv("HOST_PROC", hostMappingPath+"/proc")
	}
}

// GetFileInHost means add the host root mapping prefix, it's dependent when the rover is deploy in a container
func GetFileInHost(absPath string) string {
	if hostMappingPath != "" && strings.HasPrefix(absPath, hostMappingPath) {
		return absPath
	}
	return hostMappingPath + absPath
}
