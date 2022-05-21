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
	"fmt"
	"path/filepath"
	"sync"

	"github.com/apache/skywalking-rover/pkg/logger"
	"github.com/apache/skywalking-rover/pkg/tools/operator"

	"github.com/cilium/ebpf"
)

//go:embed *
var assets embed.FS

var (
	customizedBTFData []byte
	findBTFOnce       sync.Once

	log = logger.GetLogger("tools", "btf")
)

func GetEBPFCollectionOptionsIfNeed() *ebpf.CollectionOptions {
	findBTFOnce.Do(func() {
		btfPath, isCustomizedBTF, err := getKernelBTFAddress()
		if err != nil {
			log.Warnf("found BTF failure: %v", err)
			return
		}

		if !isCustomizedBTF {
			return
		}
		d, err := asset(btfPath)
		if err != nil {
			log.Warnf("could not found the customized BTF file: %s", btfPath)
			return
		}
		customizedBTFData = d
	})

	if customizedBTFData == nil {
		return nil
	}

	return &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{TargetBTF: bytes.NewReader(customizedBTFData)}}
}

// getKernelBTFAddress means get the kernel BTF file path
func getKernelBTFAddress() (btfPath string, isCustomizedBTF bool, err error) {
	path, err := ExistKernelBTF()
	if err == nil {
		return path, false, nil
	}

	distributeInfo, err := operator.GetDistributionInfo()
	if err != nil {
		return "", false, fmt.Errorf("could not load the system distribute info: %v", err)
	}
	uname, err := operator.GetOSUname()
	if err != nil {
		return "", false, fmt.Errorf("could not load the uname info: %v", err)
	}

	btfPath = fmt.Sprintf("files/%s/%s/%s/%s.btf", distributeInfo.Name, distributeInfo.Version,
		distributeInfo.Architecture, uname.Release)
	_, err = asset(btfPath)
	if err != nil {
		return "", true, fmt.Errorf("could not found customized BTF file: %s", btfPath)
	}
	return btfPath, true, nil
}

func asset(file string) ([]byte, error) {
	return assets.ReadFile(filepath.ToSlash(file))
}
