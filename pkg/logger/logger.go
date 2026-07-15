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
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	// root is the base logger; its level follows the global "logger.level" config.
	root = initializeLogger(DefaultLoggerLevel)
	// debugRoot is always at DebugLevel. A module elevated through
	// "logger.debug_modules" binds its whole entry here, so ALL of its levels
	// (debug included) are emitted regardless of the global level.
	debugRoot = initializeLogger(logrus.DebugLevel)

	// registry keeps every logger created(most are package-level vars created at
	// import time, i.e. before setupLogger runs) so the debug allowlist can be
	// re-applied once the config is loaded.
	registryMux   sync.Mutex
	registry      []*Logger
	debugPrefixes []string
)

type Logger struct {
	*logrus.Entry
	moduleString string
}

// GetLogger for the module
func GetLogger(modules ...string) *Logger {
	moduleString := ""
	if len(modules) > 0 {
		moduleString = strings.Join(modules, ".")
	}
	l := &Logger{moduleString: moduleString}
	l.apply()

	registryMux.Lock()
	registry = append(registry, l)
	registryMux.Unlock()
	return l
}

// apply (re)binds the underlying entry: a module in the debug allowlist logs
// through debugRoot(always DebugLevel), every other module through root(gated by
// the global level). Binding the whole entry - rather than overriding only the
// debug methods - keeps the level semantics monotonic: an elevated module never
// drops its own info/warn lines while still emitting debug.
func (l *Logger) apply() {
	base := root
	if matchDebugModule(l.moduleString) {
		base = debugRoot
	}
	l.Entry = base.WithField("module", l.moduleString)
}

func (l *Logger) Enable(level logrus.Level) bool {
	return l.Logger.IsLevelEnabled(level)
}

// matchDebugModule reports whether the module(or one of its parent modules) is
// in the configured debug allowlist. Matching is on module-segment boundaries,
// so prefix "accesslog.collector" matches "accesslog.collector" and
// "accesslog.collector.ztunnel" but not "accesslog.collectorx".
func matchDebugModule(moduleString string) bool {
	for _, p := range debugPrefixes {
		if p == "" {
			continue
		}
		if moduleString == p || strings.HasPrefix(moduleString, p+".") {
			return true
		}
	}
	return false
}
