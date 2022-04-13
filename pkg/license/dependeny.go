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
	"path/filepath"

	"github.com/apache/skywalking-eyes/pkg/deps"
)

type Group struct {
	Name     string   `mapstructure:"name"`
	Licenses []string `mapstructure:"license"`
}

type DependencyGroup struct {
	Name string
	Deps []*Dependency
}

type Dependency struct {
	GroupName      string
	Name           string
	Version        string
	Location       string
	LicenseID      string
	LicenseContent string
}

func CombineDependency(d []*deps.Result, groups []*Group) map[string]*DependencyGroup {
	result := make(map[string]*DependencyGroup)
	for _, r := range d {
		d := NewDependency(r, groups)
		group := result[d.GroupName]
		if group == nil {
			group = &DependencyGroup{
				Name: d.GroupName,
				Deps: make([]*Dependency, 0),
			}
			result[d.GroupName] = group
		}
		group.Deps = append(group.Deps, d)
	}
	return result
}

func NewDependency(dep *deps.Result, licenseGroups []*Group) *Dependency {
	groupName := dep.LicenseSpdxID
	if groupName != "" {
		// dynamic combine license name
		for _, group := range licenseGroups {
			for _, id := range group.Licenses {
				if id == groupName {
					groupName = group.Name
				}
			}
		}
	}

	return &Dependency{
		GroupName:      groupName,
		Name:           identityPattern.ReplaceAllString(dep.Dependency, "-"),
		Version:        dep.Version,
		Location:       fmt.Sprintf("https://%s", dep.Dependency),
		LicenseID:      dep.LicenseSpdxID,
		LicenseContent: dep.LicenseContent,
	}
}

func (d *Dependency) ignoreWriteLicense() bool {
	return d.GroupName == "Apache 2.0"
}

func (d *Dependency) writeLicense(dir string) error {
	filename := string(identityPattern.ReplaceAll([]byte(d.Name), []byte("-")))
	filename = filepath.Join(dir, "license-"+filename+".txt")
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create license file %v: %v", filename, err)
	}

	defer func(file *os.File) { _ = file.Close() }(file)
	_, err = file.WriteString(d.LicenseContent)
	if err != nil {
		return fmt.Errorf("failed to write license file, %v: %v", filename, err)
	}
	return nil
}
