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

package config

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	conf *viper.Viper
}

// Load config from file
func Load(file string) (*Config, error) {
	absolutePath, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, err
	}
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(content)); err != nil {
		return nil, err
	}

	// env replace
	overrideEnv(v)

	return &Config{conf: v}, nil
}

// GetTopLevelKeys from config
func (c *Config) GetTopLevelKeys() []string {
	settings := c.conf.AllSettings()
	keys := make([]string, 0)
	for k := range settings {
		keys = append(keys, k)
	}
	return keys
}

// UnMarshalWithKey to the config value reference
func (c *Config) UnMarshalWithKey(key string, val interface{}) error {
	return c.conf.UnmarshalKey(key, val)
}
