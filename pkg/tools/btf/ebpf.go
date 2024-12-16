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
	"bytes"
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/operator"
)

//go:embed *
var assets embed.FS

var (
	spec        *btf.Spec
	findBTFOnce sync.Once

	log = logger.GetLogger("tools", "btf")
)

func LoadBPFAndAssign(loadBPF func() (*ebpf.CollectionSpec, error), objs interface{}) error {
	bpf, err := loadBPF()
	if err != nil {
		return err
	}

	return bpf.LoadAndAssign(objs, GetEBPFCollectionOptionsIfNeed(bpf))
}

func GetEBPFCollectionOptionsIfNeed(bpfSpec *ebpf.CollectionSpec) *ebpf.CollectionOptions {
	findBTFOnce.Do(func() {
		readSpec, err := getKernelBTFAddress()
		if err != nil {
			log.Warnf("found BTF failure: %v", err)
			return
		}

		spec = readSpec
	})

	enhanceDataQueueOpts(bpfSpec)
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
	bpfObjBuff, err := asset(path)
	if err != nil {
		return nil, fmt.Errorf("could not found customized BTF file: %s", path)
	}
	spec, err = btf.LoadSpecFromReader(bytes.NewReader(bpfObjBuff))
	if err != nil {
		return nil, fmt.Errorf("could not load customized BTF file: %s", path)
	}
	return spec, nil
}

func asset(file string) ([]byte, error) {
	return assets.ReadFile(filepath.ToSlash(file))
}

func validateGlobalConstVoidPtrVar(t btf.Type) error {
	btfVar, ok := t.(*btf.Var)
	if !ok {
		return errors.New("not of type btf.Var")
	}

	if btfVar.Linkage != btf.GlobalVar {
		return fmt.Errorf("%q is not a global variable", btfVar.Name)
	}

	btfPtr, ok := btfVar.Type.(*btf.Pointer)
	if !ok {
		return fmt.Errorf("%q is not a pointer", btfVar.Name)
	}

	btfConst, ok := btfPtr.Target.(*btf.Const)
	if !ok {
		return fmt.Errorf("%q is not const", btfVar.Name)
	}

	_, ok = btfConst.Type.(*btf.Void)
	if !ok {
		return fmt.Errorf("%q is not a const void pointer", btfVar.Name)
	}

	return nil
}
