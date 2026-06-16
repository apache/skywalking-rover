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
	"reflect"
	"testing"
	"time"

	"github.com/apache/skywalking-rover/pkg/module"
)

const (
	moduleTest1 = "test1"
	moduleTest2 = "test2"
	moduleTest3 = "test3"
)

func TestResolveDependency(t *testing.T) {
	tests := []testDependencyStruct{
		{
			name: "no dependency",
			moduleWithDependencies: map[string][]string{
				moduleTest1: nil,
				moduleTest2: nil,
			},
			setupModules: []string{
				moduleTest1, moduleTest2,
			},
			expectSequence: []string{
				moduleTest1, moduleTest2,
			},
		},
		{
			name: "test1 on test2",
			moduleWithDependencies: map[string][]string{
				moduleTest1: {moduleTest2},
				moduleTest2: nil,
			},
			setupModules: []string{
				moduleTest1, moduleTest2,
			},
			expectSequence: []string{
				moduleTest2, moduleTest1,
			},
		},
		{
			name: "test1 depend on test2, and other no depend test3",
			moduleWithDependencies: map[string][]string{
				moduleTest1: {moduleTest2},
				moduleTest2: nil,
				moduleTest3: nil,
			},
			setupModules: []string{
				moduleTest1, moduleTest2, moduleTest3,
			},
			expectSequence: []string{
				moduleTest2, moduleTest1, moduleTest3,
			},
		},
		{
			name: "test1 depend on test2 and test2 depend on test3",
			moduleWithDependencies: map[string][]string{
				moduleTest1: {moduleTest2},
				moduleTest2: {moduleTest3},
				moduleTest3: nil,
			},
			setupModules: []string{
				moduleTest1, moduleTest2, moduleTest3,
			},
			expectSequence: []string{
				moduleTest3, moduleTest2, moduleTest1,
			},
		},
		{
			name: "test1 depend on test2 and test3, and test2 depend on test3",
			moduleWithDependencies: map[string][]string{
				moduleTest1: {moduleTest2, moduleTest3},
				moduleTest2: {moduleTest3},
				moduleTest3: nil,
			},
			setupModules: []string{
				moduleTest1, moduleTest2, moduleTest3,
			},
			expectSequence: []string{
				moduleTest3, moduleTest2, moduleTest1,
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDependency(&tests[i], t)
		})
	}
}

type testDependencyStruct struct {
	name string

	moduleWithDependencies map[string][]string
	setupModules           []string
	expectSequence         []string
}

func testDependency(testDependency *testDependencyStruct, t *testing.T) {
	// register the modules
	for name, dependencies := range testDependency.moduleWithDependencies {
		module.Register(&testModule{name: name, dependencies: dependencies})
	}

	// build module list
	modules := make([]module.Module, 0)
	for _, name := range testDependency.setupModules {
		modules = append(modules, module.FindModule(name))
	}

	// resolve dependency
	starter := NewModuleStarter(modules)
	if err := starter.ResolveDependency(); err != nil {
		t.Fatalf("resolve dependency sequence failure: %v", err)
	}

	// except sequence
	exceptSequence := make([]module.Module, 0)
	for _, name := range testDependency.expectSequence {
		exceptSequence = append(exceptSequence, module.FindModule(name))
	}

	if !reflect.DeepEqual(exceptSequence, starter.orderedModules) {
		t.Fatalf("startup sequence not same: \nexcept: \n%v\n actual: \n%v", exceptSequence, starter.orderedModules)
	}
}

func TestRun(t *testing.T) {
	tests := []testRunStruct{
		{
			name: "simple and shutdown by module",
			dependencies: map[string][]string{
				moduleTest1: nil,
				moduleTest2: nil,
			},
			modules: []string{
				moduleTest1, moduleTest2,
			},
			startSequence: []string{
				moduleTest1, moduleTest2,
			},
			startNotifySequence: []string{
				moduleTest1, moduleTest2,
			},
			shutdownSequence: []string{
				moduleTest2, moduleTest1,
			},
			triggerShutdown: func(_ context.Context, _ context.CancelFunc, starter *ModuleStarter) {
				starter.moduleManager.ShutdownModules(nil)
			},
		},
		{
			name: "simple and shutdown by context.down",
			dependencies: map[string][]string{
				moduleTest1: nil,
				moduleTest2: nil,
			},
			modules: []string{
				moduleTest1, moduleTest2,
			},
			startSequence: []string{
				moduleTest1, moduleTest2,
			},
			startNotifySequence: []string{
				moduleTest1, moduleTest2,
			},
			shutdownSequence: []string{
				moduleTest2, moduleTest1,
			},
			triggerShutdown: func(_ context.Context, cancel context.CancelFunc, _ *ModuleStarter) {
				cancel()
			},
		},
		{
			name: "dependency with module shutdown",
			dependencies: map[string][]string{
				moduleTest1: {moduleTest2},
				moduleTest2: nil,
			},
			modules: []string{
				moduleTest1, moduleTest2,
			},
			startSequence: []string{
				moduleTest2, moduleTest1,
			},
			startNotifySequence: []string{
				moduleTest2, moduleTest1,
			},
			shutdownSequence: []string{
				moduleTest1, moduleTest2,
			},
			triggerShutdown: func(_ context.Context, _ context.CancelFunc, starter *ModuleStarter) {
				starter.moduleManager.ShutdownModules(nil)
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testRun(&tests[i], t)
		})
	}
}

type testRunStruct struct {
	name                string
	dependencies        map[string][]string
	modules             []string
	startSequence       []string
	startNotifySequence []string
	shutdownSequence    []string
	triggerShutdown     func(ctx context.Context, cancel context.CancelFunc, starter *ModuleStarter)
}

func testRun(run *testRunStruct, t *testing.T) {
	sequence := &sequenceMonitor{}
	for name, dependencies := range run.dependencies {
		module.Register(&testModule{name: name, dependencies: dependencies, sequence: sequence})
	}

	// build module list
	modules := make([]module.Module, 0)
	for _, name := range run.modules {
		modules = append(modules, module.FindModule(name))
	}

	ctx := context.Background()
	ctx, cancelFunc := context.WithCancel(ctx)
	shutdownChannel := make(chan error)
	starter := NewModuleStarter(modules)
	go func() {
		err := starter.Run(ctx, nil)
		if err != nil {
			shutdownChannel <- err
		} else {
			close(shutdownChannel)
		}
	}()

	// wait 1 second to run
	time.Sleep(1 * time.Second)

	// trigger shutdown
	run.triggerShutdown(ctx, cancelFunc, starter)

	// wait shutdown
	select {
	case <-time.After(1 * time.Second):
		t.Fatalf("the shutdown not triggerd")
	case err := <-shutdownChannel:
		if err != nil {
			t.Fatalf("the module running failure: %v", err)
		}
	}

	// validate sequence
	if !reflect.DeepEqual(sequence.startSequence, run.startSequence) {
		t.Fatalf("the module start sequence not right: \nexcept: \n%v\nactual:\n%v", run.startSequence, sequence.startSequence)
	}

	if !reflect.DeepEqual(sequence.startNotifySequence, run.startNotifySequence) {
		t.Fatalf("the module start sequence not right: \nexcept: \n%v\nactual:\n%v", run.startSequence, sequence.startSequence)
	}

	if !reflect.DeepEqual(sequence.shutdownSequence, run.shutdownSequence) {
		t.Fatalf("the module shutdown sequence not right: \nexcept: \n%v\nactual:\n%v", run.shutdownSequence, sequence.shutdownSequence)
	}
}

type sequenceMonitor struct {
	startSequence       []string
	startNotifySequence []string
	shutdownSequence    []string
}

func (s *sequenceMonitor) AddStartup(name string) {
	s.startSequence = append(s.startSequence, name)
}

func (s *sequenceMonitor) AddNotifyStart(name string) {
	s.startNotifySequence = append(s.startNotifySequence, name)
}

func (s *sequenceMonitor) AddShutdown(name string) {
	s.shutdownSequence = append(s.shutdownSequence, name)
}

type testModule struct {
	name         string
	dependencies []string
	sequence     *sequenceMonitor
}

func (t *testModule) Name() string {
	return t.name
}

func (t *testModule) RequiredModules() []string {
	return t.dependencies
}

func (t *testModule) Config() module.ConfigInterface {
	return &module.Config{Active: true}
}

func (t *testModule) Start(context.Context, *module.Manager) error {
	t.sequence.AddStartup(t.name)
	return nil
}

func (t *testModule) NotifyStartSuccess() {
	t.sequence.AddNotifyStart(t.name)
}

func (t *testModule) Shutdown(context.Context, *module.Manager) error {
	t.sequence.AddShutdown(t.name)
	return nil
}
