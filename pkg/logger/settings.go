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

const (
	DefaultLoggerLevel = logrus.InfoLevel
)

type Config struct {
	// Level is the global lowest level that is allowed to be printed.
	Level string `mapstructure:"level"`
	// DebugModules is a comma separated list of module(name prefix) to elevate to
	// the debug level regardless of Level, e.g. "accesslog.collector.ztunnel".
	// This keeps the high volume modules quiet(bounding the logging allocation
	// churn) while still getting debug detail for the modules under investigation.
	DebugModules string `mapstructure:"debug_modules"`
}

// setupLogger when Bootstrap
func setupLogger(config *Config) (err error) {
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return err
	}
	root.SetLevel(level)
	// debugRoot stays at DebugLevel; only the allowlist decides who uses it.

	debugPrefixes = parseDebugModules(config.DebugModules)
	// re-apply the allowlist to the loggers created before the config was loaded
	// (package-level GetLogger vars run at import time).
	registryMux.Lock()
	for _, l := range registry {
		l.apply()
	}
	registryMux.Unlock()
	return nil
}

func parseDebugModules(value string) []string {
	res := make([]string, 0)
	for _, p := range strings.Split(value, ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func initializeLogger(level logrus.Level) *logrus.Logger {
	l := logrus.New()
	l.SetLevel(level)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	return l
}

func (c *Config) IsActive() bool {
	return true
}
