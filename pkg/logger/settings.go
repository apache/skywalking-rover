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

import "github.com/sirupsen/logrus"

const (
	DefaultLoggerLevel = logrus.InfoLevel
)

type Config struct {
	Level string `mapstructure:"level"`
}

// setupLogger when Bootstrap
func setupLogger(config *Config) (err error) {
	return updateLogger(root, config)
}

func updateLogger(log *logrus.Logger, config *Config) error {
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return err
	}
	log.SetLevel(level)
	return nil
}

func initializeDefaultLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(DefaultLoggerLevel)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	return l
}

func (c *Config) IsActive() bool {
	return true
}
