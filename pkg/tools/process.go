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

package tools

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/apache/skywalking-rover/pkg/logger"
	host2 "github.com/apache/skywalking-rover/pkg/tools/host"
	"github.com/apache/skywalking-rover/pkg/tools/path"
	"github.com/apache/skywalking-rover/pkg/tools/profiling"
)

var (
	// NotSupportProfilingExe mean which program are not support for profiling
	// Not Support JIT and Script language for now
	NotSupportProfilingExe = []string{
		"java", "python", "node", "bash", "ruby", "ssh",
	}

	// executable file profiling finders
	profilingStatFinderList = []profiling.StatFinder{
		profiling.NewGoLibrary(),
	}

	// kernel profiling finder
	kernelFinder = profiling.NewKernelFinder()

	// process map file analyze(/proc/{pid}/maps)
	mapFileContentRegex = regexp.MustCompile("(?P<StartAddr>[a-f\\d]+)\\-(?P<EndAddr>[a-f\\d]+)\\s(?P<Perm>[^\\s]+)" +
		"\\s(?P<Offset>[a-f\\d]+)\\s[a-f\\d]+\\:[a-f\\d]+\\s\\d+\\s+(?P<Name>[^\\n]+)")

	log = logger.GetLogger("tools", "process")
)

// KernelFileProfilingStat is works for read the kernel and get is support for kernel symbol analyze
func KernelFileProfilingStat() (*profiling.Info, error) {
	if !kernelFinder.IsSupport(profiling.KernelSymbolFilePath) {
		return nil, fmt.Errorf("not support kernel space profiling")
	}
	return kernelFinder.Analyze(profiling.KernelSymbolFilePath)
}

// ProcessProfilingStat is validating the exe file could be profiling and get info
func ProcessProfilingStat(pid int32, exePath string) (*profiling.Info, error) {
	stat, err := os.Stat(exePath)
	if err != nil {
		return nil, fmt.Errorf("check file error: %v", err)
	}
	for _, notSupport := range NotSupportProfilingExe {
		if strings.HasPrefix(stat.Name(), notSupport) {
			return nil, fmt.Errorf("not support %s language profiling", notSupport)
		}
	}
	context := newAnalyzeContext()

	// the executable file must have the symbols
	symbols, err := context.GetFinder(exePath).AnalyzeSymbols(exePath)
	if err != nil || len(symbols) == 0 {
		return nil, fmt.Errorf("could not found any symbol in the execute file: %s, error: %v", exePath, err)
	}

	return analyzeProfilingInfo(context, pid)
}

// ProcessModules Read the profiling info of the process, without the symbol check
func ProcessModules(pid int32) ([]*profiling.Module, error) {
	context := newAnalyzeContext()
	info, err := analyzeProfilingInfo(context, pid)
	if err != nil {
		return nil, err
	}
	return info.Modules, nil
}

func analyzeProfilingInfo(context *analyzeContext, pid int32) (*profiling.Info, error) {
	// analyze process mapping
	mapFile, _ := os.Open(host2.GetFileInHost(fmt.Sprintf("/proc/%d/maps", pid)))
	scanner := bufio.NewScanner(mapFile)
	modules := make(map[string]*profiling.Module)
	for scanner.Scan() {
		submatch := mapFileContentRegex.FindStringSubmatch(scanner.Text())
		if len(submatch) != 6 {
			continue
		}
		if len(submatch[3]) > 2 && submatch[3][2] != 'x' {
			continue
		}
		moduleName := submatch[5]
		if isIgnoreModuleName(moduleName) {
			continue
		}

		// parsing range
		var err error
		moduleRange := &profiling.ModuleRange{}
		moduleRange.StartAddr, err = parseUInt64InModule(err, moduleName, "start address", submatch[1])
		moduleRange.EndAddr, err = parseUInt64InModule(err, moduleName, "end address", submatch[2])
		moduleRange.FileOffset, err = parseUInt64InModule(err, moduleName, "file offset", submatch[4])
		if err != nil {
			return nil, err
		}

		module := modules[moduleName]
		if module != nil {
			module.Ranges = append(module.Ranges, moduleRange)
			continue
		}
		modulePath := host2.GetFileInHost(fmt.Sprintf("/proc/%d/root%s", pid, moduleName))
		if !path.Exists(modulePath) {
			log.Debugf("could not found the module, ignore. name: %s, path: %s", moduleName, modulePath)
			continue
		}

		module, err = context.GetFinder(modulePath).ToModule(pid, moduleName, modulePath, []*profiling.ModuleRange{moduleRange})
		if err != nil {
			return nil, fmt.Errorf("could not init the module: %s, error: %v", moduleName, err)
		}
		modules[moduleName] = module
		//log.Debugf("found module %s in the pid %d, ranges: %d->%d", module.Name, pid, moduleRange.StartAddr, moduleRange.EndAddr)
	}
	return profiling.NewInfo(modules), nil
}

func parseUInt64InModule(err error, moduleName, key, val string) (uint64, error) {
	if err != nil {
		return 0, err
	}
	res, err := strconv.ParseUint(val, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing the %s in maps file: %s", key, moduleName)
	}
	return res, nil
}

func isIgnoreModuleName(name string) bool {
	return len(name) > 0 &&
		(strings.HasPrefix(name, "//anon") ||
			strings.HasPrefix(name, "/dev/zero") ||
			strings.HasPrefix(name, "/anon_hugepage") ||
			strings.HasPrefix(name, "[stack") ||
			strings.HasPrefix(name, "/SYSV") ||
			strings.HasPrefix(name, "[heap]") ||
			strings.HasPrefix(name, "/memfd:") ||
			strings.HasPrefix(name, "[vdso]") ||
			strings.HasPrefix(name, "[vsyscall]") ||
			strings.HasPrefix(name, "[uprobes]") ||
			strings.HasSuffix(name, ".map"))
}

type analyzeContext struct {
	pathToFinder map[string]profiling.StatFinder
}

func newAnalyzeContext() *analyzeContext {
	return &analyzeContext{
		pathToFinder: make(map[string]profiling.StatFinder),
	}
}

func (a *analyzeContext) GetFinder(name string) profiling.StatFinder {
	if f := a.pathToFinder[name]; f != nil {
		return f
	}

	// find all finders
	for _, f := range profilingStatFinderList {
		if f.IsSupport(name) {
			a.pathToFinder[name] = f
			return f
		}
	}

	// not support
	n := profiling.NewNotSupport()
	a.pathToFinder[name] = n
	return n
}
