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

	NodeName       string            `mapstructure:"node_name"`
	Namespaces     string            `mapstructure:"namespaces"`
	ClusterName    string            `mapstructure:"cluster_name"`
	Activated      string            `mapstructure:"activated"`
	Mesh           MeshConfig        `mapstructure:"mesh"`
	ExtendBuilders []*ProcessBuilder `mapstructure:"extend"`
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

// FeatureToProcessBuildersAndInit used to convert existing activated feature to the process processBuilders
func FeatureToProcessBuildersAndInit(feature string, conf *Config) ([]*ProcessBuilder, error) {
	builders := make([]*ProcessBuilder, 0)
	if feature == "mesh" {
		builders = append(builders, []*ProcessBuilder{
			{
				Filters: []string{
					".Pod.HasContainer \"istio-proxy\"",
					"eq .Container.Name \"istio-proxy\"",
				},
				Layer:        "MESH_DP",
				ServiceName:  conf.Mesh.ServiceName,
				InstanceName: "{{.Pod.Name}}",
				ProcessName:  "{{.Process.ExeName}}",
				LabelsStr:    "mesh-envoy",
			},
			{
				Filters: []string{
					".Pod.HasContainer \"istio-proxy\"",
					"ne .Container.Name \"istio-proxy\"",
				},
				Layer:        "MESH",
				ServiceName:  conf.Mesh.ServiceName,
				InstanceName: "{{.Pod.Name}}",
				ProcessName:  "{{.Process.ExeName}}",
				LabelsStr:    "mesh-application",
			},
		}...)
	} else if feature == "k8s" {
		builders = append(builders, []*ProcessBuilder{
			{
				Filters: []string{
					".Pod.HasServiceName",
				},
				Layer:        "K8S_SERVICE",
				ServiceName:  "{{.Config.ClusterName}}::{{.Pod.ServiceName}}.{{.Pod.Namespace}}",
				InstanceName: "{{.Pod.Name}}",
				ProcessName:  "{{.Process.ExeName}}",
				LabelsStr:    "k8s-service",
			},
		}...)
	} else if feature == "extend" {
		builders = append(builders, conf.ExtendBuilders...)
	} else {
		return nil, fmt.Errorf("un support feature: %s", feature)
	}

	for _, b := range builders {
		var err error
		if len(b.Filters) > 0 {
			b.FiltersBuilder = make([]*base.TemplateBuilder, 0)
			for _, f := range b.Filters {
				err = base.StringMustNotNull(err, "filter", f)
				builder, err1 := base.TemplateMustNotNull(err, "filter", fmt.Sprintf("{{%s}}", f))
				if err1 != nil {
					return nil, fmt.Errorf("build filter error: %s, error: %v", f, err1)
				}
				b.FiltersBuilder = append(b.FiltersBuilder, builder)
			}
		}
		b.ServiceNameBuilder, err = base.TemplateMustNotNull(err, "service name", b.ServiceName)
		b.InstanceNameBuilder, err = base.TemplateMustNotNull(err, "instance name", b.InstanceName)
		b.ProcessNameBuilder, err = base.TemplateMustNotNull(err, "process name", b.ProcessName)
		b.Labels = base.ParseLabels(b.LabelsStr)

		if err != nil {
			return nil, fmt.Errorf("build process builder error: %v", err)
		}
	}
	return builders, nil
}

func (c *Config) ActiveFinder() bool {
	return c.Active
}

type MeshConfig struct {
	ServiceName string `mapstructure:"service_name"`
}
