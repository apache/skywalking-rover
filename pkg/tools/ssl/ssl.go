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

package ssl

import (
	"fmt"
	"strings"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/btf"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/process"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

type handler func() (bool, error)

var log = logger.GetLogger("tools", "ssl")

type Register struct {
	pid    int
	linker *btf.Linker

	handlers map[string]handler
	modules  []*profiling.Module
}

func NewSSLRegister(pid int, linker *btf.Linker) *Register {
	return &Register{
		pid:      pid,
		linker:   linker,
		handlers: make(map[string]handler),
	}
}

func (r *Register) Execute() error {
	modules, err := process.Modules(int32(r.pid))
	if err != nil {
		return fmt.Errorf("read process modules error: %v, error: %v", r.pid, err)
	}
	r.modules = modules

	count := 0
	for name, h := range r.handlers {
		b, err := h()
		if err != nil {
			return err
		}
		if b {
			count++
			log.Debugf("success add register to process, pid: %d, name: %s", r.pid, name)
		}
	}
	if count == 0 {
		log.Debugf("cannot find any SSL register for process: %d", r.pid)
	}
	return nil
}

func (r *Register) addHandler(name string, h handler) {
	r.handlers[name] = h
}

func (r *Register) findModules(names ...string) (map[string]*profiling.Module, error) {
	result := make(map[string]*profiling.Module)
	for _, mod := range r.modules {
		for _, modName := range names {
			if strings.Contains(mod.Name, modName) {
				if !path.Exists(mod.Path) {
					return nil, fmt.Errorf("the module path not exists, path: %s", mod.Path)
				}
				result[modName] = mod
			}
		}
	}
	return result, nil
}

func (r *Register) SearchSymbol(verify stringVerify, values ...string) *profiling.Symbol {
	return r.searchSymbolInModules(r.modules, verify, values...)
}

func (r *Register) searchSymbolInModules(modules []*profiling.Module, verify stringVerify, values ...string) *profiling.Symbol {
	list := r.searchSymbolListInModules(modules, verify, values...)
	if len(list) > 0 {
		return list[0]
	}
	return nil
}

func (r *Register) searchSymbolListInModules(modules []*profiling.Module, verify stringVerify, values ...string) []*profiling.Symbol {
	var result []*profiling.Symbol
	for _, mod := range modules {
		for _, s := range mod.Symbols {
			for _, validator := range values {
				if verify(s.Name, validator) {
					result = append(result, s)
				}
			}
		}
	}
	return result
}

func (r *Register) searchSymbolNames(modules []*profiling.Module, verify stringVerify, values ...string) []string {
	list := r.searchSymbolList(modules, verify, values...)
	if len(list) > 0 {
		result := make([]string, 0)
		for _, i := range list {
			result = append(result, i.Name)
		}
		return result
	}
	return nil
}

func (r *Register) searchSymbolList(modules []*profiling.Module, verify stringVerify, values ...string) []*profiling.Symbol {
	var result []*profiling.Symbol
	for _, mod := range modules {
		for _, s := range mod.Symbols {
			for _, validator := range values {
				if verify(s.Name, validator) {
					result = append(result, s)
				}
			}
		}
	}
	return result
}

type stringVerify func(a, b string) bool
