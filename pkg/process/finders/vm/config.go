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

package vm

import (
	"regexp"

	"github.com/apache/skywalking-rover/pkg/process/finders/base"
)

type Config struct {
	base.FinderBaseConfig

	Active bool `mapstructure:"active"`

	// Check Period
	Period string `mapstructure:"period"`

	// Process finder list
	Finders []*ProcessFinderConfig `mapstructure:"finders"`
}

func (c *Config) ActiveFinder() bool {
	return c.Active
}

type ProcessFinderConfig struct {
	// Use command line to match the processes
	MatchCommandRegex string `mapstructure:"match_cmd_regex"`

	// entity
	Layer        string `mapstructure:"layer"`         // process layer
	ServiceName  string `mapstructure:"service_name"`  // process entity service name
	InstanceName string `mapstructure:"instance_name"` // process entity service instance name
	ProcessName  string `mapstructure:"process_name"`  // process entity process name

	// pre-build for build the process
	commandlineRegex    *regexp.Regexp
	serviceNameBuilder  *base.TemplateBuilder
	instanceNameBuilder *base.TemplateBuilder
	processNameBuilder  *base.TemplateBuilder
}
