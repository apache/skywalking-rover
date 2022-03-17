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

package profiling

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
)

var objDumpOutputFormat = "^([0-9a-f]+)\\s+\\w?\\s+\\w?\\s+\\S+\\s*[0-9a-f]*\\s+(\\S+)$"

// ObjDump is using `objdump` command to read
type ObjDump struct {
	commandPath string
	outputRegex *regexp.Regexp
}

func NewObjDump() *ObjDump {
	path, _ := exec.LookPath("objdump")
	compile := regexp.MustCompile(objDumpOutputFormat)
	return &ObjDump{commandPath: path, outputRegex: compile}
}

func (o *ObjDump) IsSupport(filepath string) bool {
	return o.commandPath != ""
}

func (o *ObjDump) Analyze(filepath string) (*Info, error) {
	resBytes, err := exec.Command(o.commandPath, "--syms", filepath).Output() // #nosec G204
	if err != nil {
		return nil, err
	}

	symbols := make([]*Symbol, 0)
	scanner := bufio.NewScanner(bytes.NewReader(resBytes))
	for scanner.Scan() {
		submatch := o.outputRegex.FindStringSubmatch(scanner.Text())
		if len(submatch) == 0 {
			continue
		}
		atoi, err := strconv.ParseUint(submatch[1], 16, 64)
		if err != nil {
			continue
		}
		symbols = append(symbols, &Symbol{Name: submatch[2], Location: atoi})
	}
	return newInfo(symbols), nil
}
