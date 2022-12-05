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
	"os"
	"regexp"

	"github.com/spf13/viper"
)

var EnvRegularRegex = regexp.MustCompile(`\${(?P<ENV>[_A-Z0-9]+):(?P<DEF>.*)}`)

func overrideEnv(v *viper.Viper) {
	keys := v.AllKeys()
	for _, key := range keys {
		overrideConfig(v, key, EnvRegularRegex)
	}
}

func overrideConfig(v *viper.Viper, key string, envRegex *regexp.Regexp) {
	confValue := v.Get(key)
	switch val := confValue.(type) {
	case string:
		v.Set(key, overrideString(val, envRegex))
	case []interface{}:
		v.Set(key, overrideSlice(val, envRegex))
	case int:
		v.Set(key, val)
	case bool:
		v.Set(key, val)
	}
}

func overrideSlice(val []interface{}, envRegex *regexp.Regexp) []interface{} {
	res := make([]interface{}, 0)
	for _, perValue := range val {
		switch v := perValue.(type) {
		case string:
			res = append(res, overrideString(v, envRegex))
		case map[interface{}]interface{}:
			res = append(res, overrideMapInterfaceInterface(v, envRegex))
		case map[string]interface{}:
			res = append(res, overrideMapStringInterface(v, envRegex))
		default:
			res = append(res, v)
		}
	}
	return res
}

func overrideString(val string, envRegex *regexp.Regexp) string {
	groups := envRegex.FindStringSubmatch(val)
	if len(groups) == 0 {
		return val
	}

	if v := os.Getenv(groups[1]); v != "" {
		return v
	}
	return groups[2]
}

func overrideMapInterfaceInterface(val map[interface{}]interface{}, regex *regexp.Regexp) interface{} {
	cfg := make(map[string]interface{})
	for k, v := range val {
		cfg[k.(string)] = v
	}
	return overrideMapStringInterface(cfg, regex)
}

func overrideMapStringInterface(val map[string]interface{}, regex *regexp.Regexp) map[string]interface{} {
	res := make(map[string]interface{})
	for k, v := range val {
		switch d := v.(type) {
		case string:
			res[k] = overrideString(d, regex)
		case []interface{}:
			res[k] = overrideSlice(d, regex)
		case map[string]interface{}:
			res[k] = overrideMapStringInterface(d, regex)
		case map[interface{}]interface{}:
			res[k] = overrideMapInterfaceInterface(d, regex)
		default:
			res[k] = d
		}
	}
	return res
}
