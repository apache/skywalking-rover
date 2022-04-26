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

package kubernetes

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/process/finders/base"
)

type Config struct {
	base.FinderBaseConfig

	Active bool `mapstrcture:"active"`

	NodeName   string            `mapstructure:"node_name"`
	Namespaces string            `mapstructure:"namespaces"`
	Analyzers  []*ProcessBuilder `mapstructure:"analyzers"`
}

type ProcessBuilder struct {
	Filters      []string `mapstructure:"filters"`
	Layer        string   `mapstructure:"layer"`
	ServiceName  string   `mapstructure:"service_name"`
	InstanceName string   `mapstructure:"instance_name"`
	ProcessName  string   `mapstructure:"process_name"`
	LabelsStr    string   `mapstructure:"labels"`

	// runtime
	FiltersBuilder      []*base.TemplateBuilder
	ServiceNameBuilder  *base.TemplateBuilder
	InstanceNameBuilder *base.TemplateBuilder
	ProcessNameBuilder  *base.TemplateBuilder
	Labels              []string
}

// ProcessBuildersInit used to init process builders
func ProcessBuildersInit(builders []*ProcessBuilder) error {
	for _, b := range builders {
		var err error
		if len(b.Filters) > 0 {
			b.FiltersBuilder = make([]*base.TemplateBuilder, 0)
			for _, f := range b.Filters {
				err = base.StringMustNotNull(err, "filter", f)
				builder, err1 := base.TemplateMustNotNull(err, "filter", fmt.Sprintf("{{%s}}", f))
				if err1 != nil {
					return fmt.Errorf("build filter error: %s, error: %v", f, err1)
				}
				b.FiltersBuilder = append(b.FiltersBuilder, builder)
			}
		}
		b.ServiceNameBuilder, err = base.TemplateMustNotNull(err, "service name", b.ServiceName)
		b.InstanceNameBuilder, err = base.TemplateMustNotNull(err, "instance name", b.InstanceName)
		b.ProcessNameBuilder, err = base.TemplateMustNotNull(err, "process name", b.ProcessName)
		b.Labels = base.ParseLabels(b.LabelsStr)

		if err != nil {
			return fmt.Errorf("build process builder error: %v", err)
		}
	}
	return nil
}

func (c *Config) ActiveFinder() bool {
	return c.Active
}

type MeshConfig struct {
	ServiceName string `mapstructure:"service_name"`
}
