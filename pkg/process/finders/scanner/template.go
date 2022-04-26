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

package scanner

import (
	"fmt"

	"github.com/apache/skywalking-rover/pkg/process/finders/base"
)

func renderTemplate(builder *base.TemplateBuilder, process *Process, finder *ProcessFinder) (string, error) {
	moduleManager := finder.manager.GetModuleManager()
	return builder.Execute(&TemplateContext{
		Rover:   base.NewTemplateRover(moduleManager),
		Process: base.NewTemplateProcess(moduleManager, process.OriginalProcess()),
		Finder:  &TemplateFinder{finder: finder, process: process},
	})
}

type TemplateContext struct {
	Rover   *base.TemplateRover
	Process *base.TemplateProcess
	Finder  *TemplateFinder
}

type TemplateFinder struct {
	finder  *ProcessFinder
	process *Process
}

func (t *TemplateFinder) Layer() string {
	return t.process.finderConfig.Layer
}

func (t *TemplateFinder) RegexMatchGroup(inx int) (string, error) {
	submatch := t.process.finderConfig.commandlineRegex.FindStringSubmatch(t.process.cmd)
	if len(submatch) == 0 || inx+1 >= len(submatch) {
		return "", fmt.Errorf("could not find match")
	}
	return submatch[inx], nil
}
