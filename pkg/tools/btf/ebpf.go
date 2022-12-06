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

package btf

import (
	"embed"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf/btf"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/operator"

	"github.com/cilium/ebpf"
)

//go:embed *
var assets embed.FS

var (
	spec        *btf.Spec
	findBTFOnce sync.Once

	log = logger.GetLogger("tools", "btf")
)

func GetEBPFCollectionOptionsIfNeed() *ebpf.CollectionOptions {
	findBTFOnce.Do(func() {
		readSpec, err := getKernelBTFAddress()
		if err != nil {
			log.Warnf("found BTF failure: %v", err)
			return
		}

		spec = readSpec
	})

	return &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: spec}}
}

// getKernelBTFAddress means get the kernel BTF file path
func getKernelBTFAddress() (spec *btf.Spec, err error) {
	spec, err = btf.LoadKernelSpec()
	if err == nil {
		return spec, nil
	}

	distributeInfo, err := operator.GetDistributionInfo()
	if err != nil {
		return nil, fmt.Errorf("could not load the system distribute info: %v", err)
	}
	uname, err := operator.GetOSUname()
	if err != nil {
		return nil, fmt.Errorf("could not load the uname info: %v", err)
	}

	path := fmt.Sprintf("files/%s/%s/%s/%s.btf", distributeInfo.Name, distributeInfo.Version,
		distributeInfo.Architecture, uname.Release)
	_, err = asset(path)
	if err != nil {
		return nil, fmt.Errorf("could not found customized BTF file: %s", path)
	}
	return spec, nil
}

func asset(file string) ([]byte, error) {
	return assets.ReadFile(filepath.ToSlash(file))
}
