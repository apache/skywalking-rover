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

package license

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/apache/skywalking-eyes/pkg/deps"

	"github.com/apache/skywalking-rover/pkg/config"
)

var (
	//go:embed data/license-list.tpl
	licenseListTemplate string
	//go:embed data/license-header.txt
	licenseHeader string

	identityPattern = regexp.MustCompile(`[^a-zA-Z0-9\\.\-]`)
)

func GenerateDependencyLicense(confPath, declareFile, licenseBaseDir string) error {
	// make sure license output directory exists
	if err := os.MkdirAll(licenseBaseDir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}

	// load config
	conf, err := config.Load(confPath)
	if err != nil {
		return fmt.Errorf("could not load the license config: %v", err)
	}
	fixers := make([]*DependencyFixer, 0)
	if err = conf.UnMarshalWithKey("fixers", &fixers); err != nil {
		return fmt.Errorf("load all fixer failure: %v", err)
	}
	depGroups := make([]*Group, 0)
	if err = conf.UnMarshalWithKey("groups", &depGroups); err != nil {
		return fmt.Errorf("load all group failure: %v", err)
	}

	// resolve by skywalking-eyes
	report := &deps.Report{}
	configDeps := &deps.ConfigDeps{Files: []string{"go.mod"}}
	if err1 := deps.Resolve(configDeps, report); err1 != nil {
		return err1
	}

	// fix skips
	resolvedResult, err := processUnResolvedDependencies(report.Skipped, fixers)
	if err != nil {
		return err
	}

	// calculate data
	groups := CombineDependency(append(report.Resolved, resolvedResult...), depGroups)

	// render
	return renderResult(declareFile, licenseBaseDir, groups)
}

func processUnResolvedDependencies(list []*deps.Result, fixers []*DependencyFixer) ([]*deps.Result, error) {
	results := make([]*deps.Result, 0)
	notFoundDependencies := make([]string, 0)
	ctx := &DependencyFixerContext{}
	for _, d := range list {
		foundFixer := false
		for _, fixer := range fixers {
			if !fixer.Fixable(d) {
				continue
			}
			foundFixer = true
			if drop, err := fixer.Fix(ctx, d); err != nil {
				return nil, fmt.Errorf("could not fix dependency: %s, %v", d.Dependency, err)
			} else if !drop {
				results = append(results, d)
			}
			break
		}
		if !foundFixer {
			notFoundDependencies = append(notFoundDependencies, fmt.Sprintf("%s@%s", d.Dependency, d.Version))
		}
	}
	if len(notFoundDependencies) > 0 {
		return nil, fmt.Errorf("could not found dependency fixers: %s", strings.Join(notFoundDependencies, ", "))
	}
	return results, nil
}

func renderResult(licenseFile, licensesBaseDir string, groups map[string]*DependencyGroup) error {
	if _, e := os.Stat(licenseFile); e == nil {
		if err := os.Remove(licenseFile); err != nil {
			return err
		}
	}
	declareRealFile, err := os.Create(licenseFile)
	if err != nil {
		return err
	}
	defer declareRealFile.Close()
	if _, err = declareRealFile.WriteString(licenseHeader); err != nil {
		return err
	}
	licenseTpl, err := template.New("licenseRender").Parse(licenseListTemplate)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if err := licenseTpl.Execute(declareRealFile, group); err != nil {
			return err
		}
	}

	// add output license
	for _, group := range groups {
		for _, dep := range group.Deps {
			if dep.ignoreWriteLicense() {
				continue
			}
			if err := dep.writeLicense(licensesBaseDir); err != nil {
				return err
			}
		}
	}
	return nil
}
