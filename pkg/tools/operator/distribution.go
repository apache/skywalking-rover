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

package operator

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/apache/skywalking-rover/pkg/tools/host"
)

type DistributionInfo struct {
	Name         string // ubuntu, debian, etcd.
	Version      string // 20.04, 7, etcd.
	Architecture string // x86_64, etcd.
}

// GetDistributionInfo of machine
func GetDistributionInfo() (*DistributionInfo, error) {
	var result = &DistributionInfo{}
	tryingToFindDistributionByReleaseFile(result, "/etc/lsb-release", "DISTRIB_ID", "DISTRIB_RELEASE", "")
	tryingToFindDistributionByReleaseFile(result, "/etc/os-release", "ID", "VERSION_ID", "")

	tryingToFindDistributionByCommand(result, "Distributor ID", "Release", "", "lsb_release", "-a")
	tryingToFindDistributionByCommand(result, "", "", "Architecture", "hostnamectl")
	tryingToFindDistributionByCommand(result, "", "", "Architecture", "")

	// fix arch
	fixArchByCommand(result, "arch")
	fixArchByCommand(result, "uname", "-m")

	if !result.AllDataSuccess() {
		return nil, fmt.Errorf("incomplete data, current existing data: %v", result)
	}
	result.Normalize()
	return result, nil
}

func tryingToFindDistributionByReleaseFile(data *DistributionInfo, filename, nameKey, versionKey, architectureKey string) {
	if data.AllDataSuccess() {
		return
	}
	file, err := os.Open(host.GetFileInHost(filename))
	if err != nil {
		return
	}
	content := splitData(file, "=")
	fixData(data, content, nameKey, versionKey, architectureKey)
}

func tryingToFindDistributionByCommand(data *DistributionInfo, nameKey, versionKey, architectureKey, commandName string, args ...string) {
	if data.AllDataSuccess() {
		return
	}
	output := executeCommand(commandName, args...)
	content := splitData(bytes.NewReader(output), ":")
	fixData(data, content, nameKey, versionKey, architectureKey)
}

func executeCommand(name string, args ...string) []byte {
	c := exec.Command(name, args...)
	output, err := c.CombinedOutput()
	if err == nil {
		return output
	}
	return nil
}

func fixArchByCommand(data *DistributionInfo, commandName string, args ...string) {
	if data.Architecture != "" {
		return
	}
	data.Architecture = string(executeCommand(commandName, args...))
}

func fixData(d *DistributionInfo, content map[string]string, name, version, architecture string) {
	if d.Name == "" && content[name] != "" {
		d.Name = content[name]
	}
	if d.Version == "" && content[version] != "" {
		d.Version = content[version]
	}
	if d.Architecture == "" && content[architecture] != "" {
		d.Architecture = content[architecture]
	}
}

func splitData(r io.Reader, dataSplit string) map[string]string {
	scanner := bufio.NewScanner(r)
	result := make(map[string]string)
	for scanner.Scan() {
		split := strings.Split(scanner.Text(), dataSplit)
		if len(split) != 2 {
			continue
		}
		result[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
	}
	return result
}

func (d *DistributionInfo) AllDataSuccess() bool {
	return d.Name != "" && d.Version != "" && d.Architecture != ""
}

func (d *DistributionInfo) Normalize() {
	d.Name = normalizeContent(d.Name)
	d.Version = normalizeContent(d.Version)
	d.Architecture = normalizeContent(d.Architecture)
}

func normalizeContent(d string) string {
	d = strings.TrimSpace(d)
	d = strings.ToLower(d)
	d = strings.ReplaceAll(d, "-", "_")
	d = strings.TrimPrefix(d, "\"")
	d = strings.TrimSuffix(d, "\"")
	return d
}
