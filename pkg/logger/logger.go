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

package logger

import (
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	root = initializeDefaultLogger()
)

type Logger struct {
	*logrus.Entry
	module []string
}

// GetLogger for the module
func GetLogger(modules ...string) *Logger {
	moduleString := ""
	if len(modules) > 0 {
		moduleString = strings.Join(modules, ".")
	}
	return &Logger{Entry: root.WithField("module", moduleString), module: modules}
}

func (l *Logger) Enable(level logrus.Level) bool {
	return root.IsLevelEnabled(level)
}
