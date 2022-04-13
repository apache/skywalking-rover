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
	"bytes"
	"encoding/json"
	"fmt"
	"go/build"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/apache/skywalking-eyes/pkg/deps"
	"golang.org/x/tools/go/packages"
)

// nolint
var possibleLicenseFileName = regexp.MustCompile(`(?i)^LICENSE|LICENCE(\.txt)?|COPYING(\.txt)?$`)

type DependencyFixer struct {
	Name      string `mapstructure:"name"`
	Version   string `mapstructure:"version"`
	Ignore    bool   `mapstructure:"ignore"`
	LicenseID string `mapstructure:"license"`
}

type DependencyFixerContext struct {
	modules []*packages.Module
}

func (d *DependencyFixerContext) initAllModulesIfNeed() error {
	if d.modules != nil {
		return nil
	}
	output, err := exec.Command("go", "mod", "download", "-json").Output()
	if err != nil {
		return err
	}

	modules := make([]*packages.Module, 0)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var m packages.Module
		if err := decoder.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		modules = append(modules, &m)
	}

	d.modules = modules
	return nil
}

func (d *DependencyFixerContext) GetModule(name string) (*packages.Module, error) {
	if err := d.initAllModulesIfNeed(); err != nil {
		return nil, err
	}
	for _, m := range d.modules {
		if m.Path == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("could not found the dependency: %s", name)
}

func (d *DependencyFixer) Fixable(dep *deps.Result) bool {
	return dep.Dependency == d.Name && dep.Version == d.Version
}

// Fix the Dependency Result
// If ignore the Dependency then return true
func (d *DependencyFixer) Fix(ctx *DependencyFixerContext, dep *deps.Result) (drop bool, err error) {
	if d.Ignore {
		return true, nil
	}
	module, err := ctx.GetModule(dep.Dependency)
	if err != nil {
		return false, err
	}
	if module == nil {
		return false, fmt.Errorf("could not found dependency")
	}

	dir := module.Dir

	for {
		files, err := os.ReadDir(dir)
		if err != nil {
			return false, err
		}
		for _, info := range files {
			if !possibleLicenseFileName.MatchString(info.Name()) {
				continue
			}
			licenseFilePath := filepath.Join(dir, info.Name())
			content, err := os.ReadFile(licenseFilePath)
			if err != nil {
				return false, err
			}

			dep.LicenseFilePath = licenseFilePath
			dep.LicenseContent = string(content)
			dep.LicenseSpdxID = d.LicenseID
			return false, nil
		}
		if dir == module.Dir || dir == build.Default.GOPATH {
			return false, fmt.Errorf("could not found license file")
		}
		dir = filepath.Dir(dir)
	}
}
