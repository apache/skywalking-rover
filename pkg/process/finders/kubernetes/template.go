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
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/process/finders/base"

	"github.com/shirou/gopsutil/process"

	"k8s.io/apimachinery/pkg/labels"
)

func executeFilter(builders []*base.TemplateBuilder, p *process.Process, pc *PodContainer, finder *ProcessFinder) (bool, error) {
	if len(builders) == 0 {
		return true, nil
	}

	moduleManager := finder.manager.GetModuleManager()
	for _, b := range builders {
		result, err := b.Execute(&FilterContext{
			Process:   base.NewTemplateProcess(moduleManager, p),
			Pod:       &TemplatePodJudgment{&TemplatePod{pc, finder}},
			Container: &TemplateContainer{pc},
		})
		if err != nil {
			return false, err
		}

		success, err := strconv.ParseBool(result)
		if err != nil {
			return false, err
		}

		// must all filtering success
		// if have any false, just short circuit
		if !success {
			return false, nil
		}
	}
	return true, nil
}

func renderTemplate(builder *base.TemplateBuilder, p *process.Process, pc *PodContainer, finder *ProcessFinder) (string, error) {
	moduleManager := finder.manager.GetModuleManager()
	return builder.Execute(&EntityRenderContext{
		Rover:     base.NewTemplateRover(moduleManager),
		Process:   base.NewTemplateProcess(moduleManager, p),
		Pod:       &TemplatePod{pc, finder},
		Container: &TemplateContainer{pc},
		Config:    &TemplateConfig{finder.conf},
	})
}

type FilterContext struct {
	Process   *base.TemplateProcess
	Pod       *TemplatePodJudgment
	Container *TemplateContainer
}

type TemplateConfig struct {
	conf *Config
}

func (t *TemplateConfig) ClusterName() string {
	return t.conf.ClusterName
}

type EntityRenderContext struct {
	Rover     *base.TemplateRover
	Process   *base.TemplateProcess
	Pod       *TemplatePod
	Container *TemplateContainer
	Config    *TemplateConfig
}

type TemplatePod struct {
	pc     *PodContainer
	finder *ProcessFinder
}

func (p *TemplatePod) Name() string {
	return p.pc.Pod.Name
}

func (p *TemplatePod) Namespace() string {
	return p.pc.Pod.Namespace
}

func (p *TemplatePod) Node() string {
	return p.pc.Pod.Spec.NodeName
}

func (p *TemplatePod) LabelValue(names string) (string, error) {
	namesArray := strings.Split(names, ",")
	for _, name := range namesArray {
		val := p.pc.Pod.Labels[name]
		if val != "" {
			return val, nil
		}
	}
	actualNames := make([]string, 0)
	for k := range p.pc.Pod.Labels {
		actualNames = append(actualNames, k)
	}
	return "", fmt.Errorf("could not found matches label, want names: %v, actual names: %v", namesArray, actualNames)
}

func (p *TemplatePod) ServiceName() string {
	return p.pc.ServiceName()
}

func (p *TemplatePod) OwnerName(kindNames string) (string, error) {
	kindNameArray := strings.Split(kindNames, ",")
	for _, name := range kindNameArray {
		if strings.EqualFold(name, "service") {
			if s := p.ServiceName(); s != "" {
				return s, nil
			}
			continue
		}
		if owner, err := p.pc.FindOwner(p.finder.ctx, name, p.finder.k8sConfig); err != nil {
			return "", err
		} else if owner != nil {
			return owner.Name, nil
		}
	}
	return "", fmt.Errorf("could not found owner in %v", kindNameArray)
}

type TemplatePodJudgment struct {
	*TemplatePod
}

func (t *TemplatePodJudgment) HasContainer(name string) bool {
	// nolint
	for _, c := range t.pc.Pod.Spec.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}

func (t *TemplatePodJudgment) LabelSelector(selector string) (bool, error) {
	labelsMap, err := labels.ConvertSelectorToLabelsMap(selector)
	if err != nil {
		return false, err
	}
	return labelsMap.AsSelector().Matches(labels.Set(t.pc.Pod.Labels)), nil
}

func (t *TemplatePodJudgment) HasServiceName() bool {
	return t.ServiceName() != ""
}

type TemplateContainer struct {
	pc *PodContainer
}

func (c *TemplateContainer) Name() string {
	return c.pc.ContainerSpec.Name
}

func (c *TemplateContainer) ID() string {
	return c.pc.ContainerStatus.ContainerID
}
