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
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/module"
)

type ModuleStarter struct {
	original []module.Module

	activeModules  []module.Module
	moduleMap      map[string]module.Module
	visited        map[string]bool
	orderedModules []module.Module
	startedModules []module.Module
	moduleManager  *module.Manager
}

func NewModuleStarter(modules []module.Module) *ModuleStarter {
	activeModules := make([]module.Module, 0)
	for _, mod := range modules {
		if mod.Config().IsActive() {
			activeModules = append(activeModules, mod)
		}
	}
	moduleMap := make(map[string]module.Module)
	for _, mod := range modules {
		moduleMap[mod.Name()] = mod
	}
	return &ModuleStarter{
		original:       modules,
		activeModules:  activeModules,
		moduleMap:      moduleMap,
		orderedModules: make([]module.Module, 0),
		visited:        make(map[string]bool),
		startedModules: make([]module.Module, 0),
	}
}

func (m *ModuleStarter) Run(ctx context.Context, startUpSuccessCallback func(*module.Manager)) error {
	// resolve module dependencies
	if err := m.ResolveDependency(); err != nil {
		return err
	}

	if len(m.orderedModules) == 0 {
		return fmt.Errorf("no module is active")
	}

	shutdownChannel := make(chan error)
	m.moduleManager = module.NewManager(m.orderedModules, func(err error) {
		shutdownChannel <- err
	})

	// startup modules
	defer m.shutdownModules(ctx)
	for _, module := range m.orderedModules {
		moduleName := module.Name()
		// start module
		log.Debugf("starting module %s", moduleName)
		if err := module.Start(ctx, m.moduleManager); err != nil {
			return fmt.Errorf("start module %s failure: %v", moduleName, err)
		}

		log.Infof("module %s start successful", moduleName)

		// append to started modules
		m.startedModules = append(m.startedModules, module)
	}

	// notify all modules setup success
	for _, mod := range m.startedModules {
		mod.NotifyStartSuccess()
	}
	if startUpSuccessCallback != nil {
		startUpSuccessCallback(m.moduleManager)
	}

	// register terminal
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		select {
		case <-signals:
			log.Infof("detect shutdown signal")
			break
		case <-ctx.Done():
			log.Infof("detect background context have been down, error by: %v", ctx.Err())
			break
		case err := <-shutdownChannel:
			log.Warnf("detect module shutdown notify: %v", err)
		}
		wg.Done()
	}()
	wg.Wait()
	return nil
}

func (m *ModuleStarter) ResolveDependency() error {
	// make the log module as first active module
	sort.Slice(m.activeModules, func(i, j int) bool {
		return m.activeModules[i].Name() == logger.ModuleName
	})

	// check has required module is not include
	for _, module := range m.activeModules {
		for _, reqModule := range module.RequiredModules() {
			if m.moduleMap[reqModule] == nil {
				return fmt.Errorf("module %s is required %s, please declare in the config", module.Name(), reqModule)
			}
		}
	}

	// append all modules
	for _, mod := range m.activeModules {
		if err := m.appendToResolve(mod, nil); err != nil {
			return err
		}
	}
	return nil
}

func (m *ModuleStarter) appendToResolve(mod, parentModule module.Module) error {
	if m.visited[mod.Name()] {
		for _, addedModule := range m.orderedModules {
			if addedModule.Name() == mod.Name() {
				return nil
			}
		}
		if parentModule == nil {
			return fmt.Errorf("found cyclic dependency in %s", mod.Name())
		}
		return fmt.Errorf("found cyclic dependency between in %s and %s", mod.Name(), parentModule.Name())
	}
	m.visited[mod.Name()] = true
	for _, requiredModule := range mod.RequiredModules() {
		if err := m.appendToResolve(m.moduleMap[requiredModule], mod); err != nil {
			return err
		}
	}
	m.orderedModules = append(m.orderedModules, mod)
	return nil
}

func (m *ModuleStarter) shutdownModules(ctx context.Context) {
	for i := len(m.startedModules) - 1; i >= 0; i-- {
		mod := m.startedModules[i]
		err := mod.Shutdown(ctx, m.moduleManager)
		if err != nil {
			log.Warnf("shutdown module %s failure: %v", mod.Name(), err)
		} else {
			log.Infof("module %s shutdown successful", mod.Name())
		}
	}
}
