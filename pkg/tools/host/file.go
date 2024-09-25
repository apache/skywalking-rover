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
	"path"
)

var (
	hostProcMappingPath string
	hostEtcMappingPath  string
)

func init() {
	hostProcMappingPath = os.Getenv("ROVER_HOST_PROC_MAPPING")
	// adapt with gopsutil framework to read the right process directory of host
	if hostProcMappingPath != "" {
		os.Setenv("HOST_PROC", hostProcMappingPath)
	}
	hostEtcMappingPath = os.Getenv("ROVER_HOST_ETC_MAPPING")
}

func GetHostProcInHost(procSubPath string) string {
	if hostProcMappingPath != "" {
		return cleanPath(hostProcMappingPath + "/" + procSubPath)
	}
	return cleanPath("/proc/" + procSubPath)
}

func GetHostEtcInHost(etcSubPath string) string {
	if hostEtcMappingPath != "" {
		return cleanPath(hostEtcMappingPath + "/" + etcSubPath)
	}
	return cleanPath("/etc/" + etcSubPath)
}

func cleanPath(p string) string {
	return path.Clean(p)
}
