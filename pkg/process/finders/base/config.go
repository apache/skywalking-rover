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
	"fmt"
	"regexp"
	"strings"
	"time"
)

type FinderBaseConfig interface {
	// ActiveFinder to detect process
	ActiveFinder() bool
}

func StringMustNotNull(err error, confKey, confValue string) error {
	if err != nil {
		return err
	}
	if confValue == "" {
		return fmt.Errorf("the %s of Scanner process must be set", confKey)
	}
	return nil
}

func TemplateMustNotNull(err error, confKey, confValue string) (*TemplateBuilder, error) {
	if err1 := StringMustNotNull(err, confKey, confValue); err1 != nil {
		return nil, err1
	}
	return NewTemplateBuilder(confKey, confValue)
}

func RegexMustNotNull(err error, confKey, confValue string) (*regexp.Regexp, error) {
	if err1 := StringMustNotNull(err, confKey, confValue); err1 != nil {
		return nil, err1
	}
	return regexp.Compile(confValue)
}

func DurationMustNotNull(err error, confKey, confValue string) (time.Duration, error) {
	if err1 := StringMustNotNull(err, confKey, confValue); err1 != nil {
		return 0, err1
	}
	return time.ParseDuration(confValue)
}

func ParseLabels(labelStr string) []string {
	tmp := strings.Split(labelStr, ",")
	result := make([]string, 0)
	for _, s := range tmp {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
