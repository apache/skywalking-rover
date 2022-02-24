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
	"reflect"
	"sort"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []testLoadConfig{
		{
			name: "no-env",
			env:  nil,
			file: "testdata/config-no-env.yaml",
			topKeys: []string{
				"testa", "testb",
			},
			unmarshalls: map[string]struct {
				newData  interface{}
				validate interface{}
			}{
				"testa": {
					newData:  &configWithString{},
					validate: &configWithString{"abc"},
				},
				"testb": {
					newData:  &configWithInteger{},
					validate: &configWithInteger{2},
				},
			},
		},
		{
			name: "env-not-set",
			env:  nil,
			file: "testdata/config-env.yaml",
			topKeys: []string{
				"testa", "testb",
			},
			unmarshalls: map[string]struct {
				newData  interface{}
				validate interface{}
			}{
				"testa": {
					newData:  &configWithString{},
					validate: &configWithString{"def"},
				},
				"testb": {
					newData:  &configWithInteger{},
					validate: &configWithInteger{456},
				},
			},
		},
		{
			name: "env-set",
			env: map[string]string{
				"TEST_A_DATA": "zzz",
				"TEST_B_DATA": "999",
			},
			file: "testdata/config-env.yaml",
			topKeys: []string{
				"testa", "testb",
			},
			unmarshalls: map[string]struct {
				newData  interface{}
				validate interface{}
			}{
				"testa": {
					newData:  &configWithString{},
					validate: &configWithString{"zzz"},
				},
				"testb": {
					newData:  &configWithInteger{},
					validate: &configWithInteger{999},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			// load config
			load, err := Load(tt.file)
			if err != nil {
				t.Fatal(err)
			}

			// valid top keys
			keys := load.GetTopLevelKeys()
			sort.Strings(keys)
			sort.Strings(tt.topKeys)
			if !reflect.DeepEqual(keys, tt.topKeys) {
				t.Fatalf("top keys not right, expect: %v, actual: %v", tt.topKeys, keys)
			}

			// unmarshalls
			for k, v := range tt.unmarshalls {
				if err := load.UnMarshalWithKey(k, v.newData); err != nil {
					t.Fatalf("load config key %s failure, %v", k, err)
				}
				if !reflect.DeepEqual(v.newData, v.validate) {
					t.Fatalf("config %s valus is not equals, expect: %v, actual: %v", k, v.validate, v.newData)
				}
			}
		})
	}
}

type testLoadConfig struct {
	name        string
	env         map[string]string
	file        string
	topKeys     []string
	unmarshalls map[string]struct {
		newData  interface{}
		validate interface{}
	}
}

type configWithString struct {
	Data string
}

type configWithInteger struct {
	Data int
}
