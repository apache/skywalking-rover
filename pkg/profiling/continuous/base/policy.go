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

package base

import (
	"reflect"
	"regexp"

	"github.com/apache/skywalking-rover/pkg/process/api"
)

type Policy struct {
	TargetProfilingType TargetProfilingType
	Items               map[CheckType]*PolicyItem

	ServicePolicy *ServicePolicy
}

type PolicyItem struct {
	Threshold string
	Period    int
	Count     int
	URIList   []string
	URIRegex  string

	Policy *Policy
}

func (p *PolicyItem) SameURIFilter(other *PolicyItem) bool {
	if p.URIRegex != "" && p.URIRegex == other.URIRegex {
		return true
	} else if len(p.URIList) > 0 && reflect.DeepEqual(p.URIList, other.URIList) {
		return true
	} else if p.URIRegex == "" && other.URIRegex == "" && len(p.URIList) == 0 && len(other.URIList) == 0 {
		return true
	}
	return false
}

type ServicePolicy struct {
	Service string
	UUID    string

	Policies  []*Policy
	Processes map[string]api.ProcessInterface
}

type URIChecker struct {
	FixedURIList []string
	URIRegexList []*regexp.Regexp
}

type URIResponseDurationTimeoutRate struct {
	Timeout int // Define how long(ms) is considered a timeout
	Rate    int // Response timeout rate
}

type TargetProfilingType string

const (
	TargetProfilingTypeOnCPU   TargetProfilingType = "ON_CPU"
	TargetProfilingTypeOffCPU  TargetProfilingType = "OFF_CPU"
	TargetProfilingTypeNetwork TargetProfilingType = "NETWORK"
)
