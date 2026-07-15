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
	hostProcMappingPath       string
	hostEtcMappingPath        string
	hostVarLogPodsMappingPath string
)

func init() {
	hostProcMappingPath = os.Getenv("ROVER_HOST_PROC_MAPPING")
	// adapt with gopsutil framework to read the right process directory of host
	if hostProcMappingPath != "" {
		os.Setenv("HOST_PROC", hostProcMappingPath)
	}
	hostEtcMappingPath = os.Getenv("ROVER_HOST_ETC_MAPPING")
	hostVarLogPodsMappingPath = os.Getenv("ROVER_HOST_VAR_LOG_PODS_MAPPING")
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

// GetHostVarLogPodsInHost resolves a path under the kubelet pod-log directory(/var/log/pods on the
// host) as seen from inside the agent container. That directory is where the kubelet writes every
// pod's container logs for ALL CRI runtimes(containerd, CRI-O, cri-dockerd), so it is the runtime
// independent place to tail the ztunnel access log. The host mount point is injected through
// ROVER_HOST_VAR_LOG_PODS_MAPPING(the same pattern as ROVER_HOST_PROC_MAPPING), so it is not
// hard-coded; when unset the real host path /var/log/pods is used.
func GetHostVarLogPodsInHost(subPath string) string {
	if hostVarLogPodsMappingPath != "" {
		return cleanPath(hostVarLogPodsMappingPath + "/" + subPath)
	}
	return cleanPath("/var/log/pods/" + subPath)
}

func cleanPath(p string) string {
	return path.Clean(p)
}
