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

package boot

import (
	"context"
	"fmt"

	"github.com/apache/skywalking-rover/pkg/config"
	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
)

var log = logger.GetLogger("boot", "starter")

func RunModules(ctx context.Context, file string) error {
	// read config files
	conf, err := config.Load(file)
	if err != nil {
		return fmt.Errorf("load config error: %s, %v", file, err)
	}

	// find all declared modules
	modules, err := findAllDeclaredModules(conf)
	if err != nil {
		return err
	}

	// startup all modules
	starter := NewModuleStarter(modules)
	return starter.Run(ctx)
}

func findAllDeclaredModules(conf *config.Config) ([]module.Module, error) {
	moduleNames := conf.GetTopLevelKeys()
	if len(moduleNames) == 0 {
		return nil, fmt.Errorf("no modules startup, please update the configuration")
	}
	modules := make([]module.Module, 0)
	for _, name := range moduleNames {
		// find module
		mod := module.FindModule(name)
		if mod == nil {
			return nil, fmt.Errorf("could not found module: %s", name)
		}
		// read config
		if err := conf.UnMarshalWithKey(name, mod.Config()); err != nil {
			return nil, fmt.Errorf("read %s module config error: %v", name, err)
		}
		modules = append(modules, mod)
	}
	return modules, nil
}
